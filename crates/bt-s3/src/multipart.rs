//! S3 multipart request scheduling, resume reconciliation, and completion.
use super::*;
use bt_tls::crypto::random;
use std::sync::{mpsc, Condvar, Mutex};

#[path = "multipart_checkpoint.rs"]
mod checkpoint;
use checkpoint::Checkpoint;

#[path = "multipart_source.rs"]
mod source;
pub(super) use source::PartReadError;
use source::{hash_field, Part, PartBody, PartPlan};

const MAX_PARTS: u64 = 10_000;
const MAX_PART_WORKERS: usize = 16;
const TOKEN_HEADER: &str = "x-amz-meta-bt-multipart-token";

/// Request budget shared by file uploads, including single PUT and multipart
/// control requests.
#[derive(Debug)]
pub struct UploadBudget {
    slots: Mutex<usize>,
    available: Condvar,
}

impl UploadBudget {
    pub fn new(limit: usize) -> Self {
        Self {
            slots: Mutex::new(limit.max(1)),
            available: Condvar::new(),
        }
    }

    fn acquire(&self, cancel: Option<&AtomicBool>) -> Result<Permit<'_>, S3Error> {
        let mut slots = self.slots.lock().unwrap();
        loop {
            if cancel.is_some_and(|flag| flag.load(Ordering::Relaxed)) {
                return Err(S3Error::cancelled());
            }
            if *slots > 0 {
                *slots -= 1;
                return Ok(Permit(self));
            }
            (slots, _) = self
                .available
                .wait_timeout(slots, Duration::from_millis(50))
                .unwrap();
        }
    }
}

struct Permit<'a>(&'a UploadBudget);

impl Drop for Permit<'_> {
    fn drop(&mut self) {
        *self.0.slots.lock().unwrap() += 1;
        self.0.available.notify_one();
    }
}

impl S3Client {
    pub(super) fn upload_call(
        &self,
        call: &Call,
        opts: &UploadOptions,
        progress: &mut dyn FnMut(u64),
    ) -> Result<Response, S3Error> {
        check_cancel(call.cancel)?;
        let _permit = opts
            .upload_budget
            .as_ref()
            .map(|budget| budget.acquire(call.cancel))
            .transpose()?;
        self.call(call, None, progress)
    }

    /// Stable identifier for an endpoint, bucket and object key. The region
    /// used for signing can be updated by redirects without changing this ID.
    pub fn upload_destination_id(&self, key: &str) -> String {
        let region = self.cfg.region.trim();
        let region = if region.is_empty() {
            "us-east-1"
        } else {
            region
        };
        let (url, _) = self.build_url(&Target::Object(key), &[], region);
        let mut hash = Sha256::new();
        for field in [
            url.to_string().as_str(),
            self.cfg.bucket.as_str(),
            region,
            key,
        ] {
            hash_field(&mut hash, field.as_bytes());
        }
        hex(&hash.finalize())
    }

    pub(super) fn clear_multipart_checkpoint(
        &self,
        key: &str,
        opts: &UploadOptions,
        cancel: &AtomicBool,
    ) -> Result<(), S3Error> {
        let Some(path) = opts.multipart_checkpoint.as_deref() else {
            return Ok(());
        };
        if let Some(old) = Checkpoint::load(path)? {
            let transfer = Transfer {
                client: self,
                key,
                opts,
                cancel,
            };
            transfer.discard(path, &old, &self.upload_destination_id(key))?;
        }
        Ok(())
    }

    pub(super) fn upload_multipart(
        &self,
        key: &str,
        source: &Path,
        size: u64,
        opts: &UploadOptions,
        progress: &mut dyn FnMut(u64),
        cancel: &AtomicBool,
    ) -> Result<String, S3Error> {
        Transfer {
            client: self,
            key,
            opts,
            cancel,
        }
        .run(source, size, progress)
    }
}

struct Transfer<'a> {
    client: &'a S3Client,
    key: &'a str,
    opts: &'a UploadOptions,
    cancel: &'a AtomicBool,
}

impl Transfer<'_> {
    fn run(
        &self,
        source: &Path,
        size: u64,
        progress: &mut dyn FnMut(u64),
    ) -> Result<String, S3Error> {
        let checkpoint_path = self.opts.multipart_checkpoint.as_deref();
        let mut create = Call::new("POST", Target::Object(self.key)).q("uploads", "");
        S3Client::object_headers(
            &mut create,
            self.opts.content_type.as_deref(),
            Some(self.opts),
        );
        create.cancel = Some(self.cancel);
        let mut plan = PartPlan::new(size, self.opts.part_size)?;
        let mut etags = vec![None; plan.parts.len()];

        let (mut checkpoint, upload_id) = if let Some(path) = checkpoint_path {
            let fingerprint = plan.fingerprint(source, &create.headers, self.cancel)?;
            let destination = self.client.upload_destination_id(self.key);
            let mut previous = None;
            if let Some(old) = Checkpoint::load(path)? {
                if old.destination == destination && old.fingerprint == fingerprint {
                    match self.reconcile(&old, &plan, &mut etags) {
                        Ok(()) => previous = Some(old),
                        Err(e)
                            if missing_upload(&e) || (old.completing && permission_denied(&e)) =>
                        {
                            if old.completing {
                                if let Some(etag) = self.find_completed(&old.token, Some(size))? {
                                    self.cleanup_completed_checkpoint(path)?;
                                    progress(size);
                                    return Ok(etag);
                                }
                            }
                            if !missing_upload(&e) {
                                return Err(e);
                            }
                            checkpoint::remove(path)?;
                        }
                        Err(e) if permission_denied(&e) => {
                            // Without ListParts we cannot validate acknowledgments or
                            // tell whether the old upload ID has expired.
                            self.discard(path, &old, &destination)?;
                        }
                        Err(e) => return Err(e),
                    }
                } else {
                    self.discard(path, &old, &destination)?;
                }
            }
            let checkpoint = if let Some(old) = previous {
                old
            } else {
                // A paginated ListParts request can fail after
                // earlier pages were already reconciled.
                etags.fill(None);
                let token = hex(&random::array::<32>().map_err(|e| S3Error::local(&e))?);
                create.headers.retain(|(name, _)| name != TOKEN_HEADER);
                let id = self.initiate(create.h(TOKEN_HEADER, &token))?;
                let mut new = Checkpoint::new(destination, fingerprint, token, id);
                if let Err(e) = new.publish(path) {
                    let _ = self.abort(&new.upload_id, None);
                    return Err(e);
                }
                new
            };
            let upload_id = checkpoint.upload_id.clone();
            (Some(checkpoint), upload_id)
        } else {
            (None, self.initiate(create)?)
        };
        let result = (|| {
            let missing = plan
                .parts
                .iter()
                .filter(|part| etags[part.number - 1].is_none())
                .collect::<Vec<_>>();
            let reused = size - missing.iter().map(|part| part.len).sum::<u64>();
            if reused > 0 {
                progress(reused);
            }
            self.upload_parts(source, &upload_id, &missing, progress, &mut |part, etag| {
                if let Some((state, path)) = checkpoint.as_mut().zip(checkpoint_path) {
                    state.record_part(path, part.number, &etag)?;
                }
                etags[part.number - 1] = Some(etag);
                Ok(())
            })?;
            check_cancel(Some(self.cancel))?;
            plan.check_source(source)?;
            if let Some((state, path)) = checkpoint.as_mut().zip(checkpoint_path) {
                state.mark_completing(path)?;
            }
            let completed = self.complete(&upload_id, &etags);
            if let (Err(e), Some(state)) = (&completed, &checkpoint) {
                if missing_upload(e) {
                    if let Some(etag) = self.find_completed(&state.token, Some(size))? {
                        return Ok(etag);
                    }
                }
            }
            completed
        })();
        if let Some(path) = checkpoint_path {
            if result.is_ok() {
                self.cleanup_completed_checkpoint(path)?;
            }
        } else if result.is_err() {
            let _ = self.abort(&upload_id, None);
        }
        result
    }

    fn cleanup_completed_checkpoint(&self, path: &Path) -> Result<(), S3Error> {
        if self.opts.retain_completed_checkpoint {
            Ok(())
        } else {
            checkpoint::remove(path)
        }
    }

    fn initiate(&self, call: Call<'_>) -> Result<String, S3Error> {
        let response = self.client.upload_call(&call, self.opts, &mut |_| {})?;
        let doc = multipart_xml(&response, "InitiateMultipartUploadResult")?;
        doc.child_text("UploadId")
            .filter(|id| !id.is_empty())
            .map(str::to_owned)
            .ok_or_else(|| {
                bad_response(&response, "CreateMultipartUpload response without UploadId")
            })
    }

    fn discard(&self, path: &Path, old: &Checkpoint, destination: &str) -> Result<(), S3Error> {
        if old.destination == destination {
            match self.abort(&old.upload_id, Some(self.cancel)) {
                Ok(()) => {}
                Err(e) if missing_upload(&e) || permission_denied(&e) => {
                    if old.completing {
                        // Even a source or policy change must preserve a conflict
                        // with a completion we cannot verify.
                        self.find_completed(&old.token, None)?;
                    }
                }
                Err(e) => return Err(e),
            }
        }
        checkpoint::remove(path)
    }

    fn abort(&self, id: &str, cancel: Option<&AtomicBool>) -> Result<(), S3Error> {
        let mut call = Call::new("DELETE", Target::Object(self.key)).q("uploadId", id);
        call.cancel = cancel;
        self.client
            .upload_call(&call, self.opts, &mut |_| {})
            .map(|_| ())
    }

    fn reconcile(
        &self,
        saved: &Checkpoint,
        plan: &PartPlan,
        etags: &mut [Option<String>],
    ) -> Result<(), S3Error> {
        let mut marker = 0;
        loop {
            let mut call =
                Call::new("GET", Target::Object(self.key)).q("uploadId", &saved.upload_id);
            if marker != 0 {
                call = call.q("part-number-marker", &marker.to_string());
            }
            call.cancel = Some(self.cancel);
            let response = self.client.upload_call(&call, self.opts, &mut |_| {})?;
            let doc = multipart_xml(&response, "ListPartsResult")?;
            for remote in doc.children_named("Part") {
                let number = part_number(remote.child_text("PartNumber")).ok_or_else(|| {
                    bad_response(&response, "ListParts response has an invalid part number")
                })?;
                let Some(part) = plan.parts.get(number - 1) else {
                    continue;
                };
                if let Some(local) = saved.etags.get(&number) {
                    // Remote parts without a matching local acknowledgment
                    // are overwritten, including lost or interrupted replies.
                    let same_etag = remote
                        .child_text("ETag")
                        .is_some_and(|tag| strip_quotes(tag) == strip_quotes(local));
                    let same_size = remote
                        .child_text("Size")
                        .and_then(|s| s.trim().parse().ok())
                        == Some(part.len);
                    etags[number - 1] = (same_etag && same_size).then(|| local.clone());
                }
            }
            match doc.child_text("IsTruncated").map(str::trim) {
                Some("true") => {
                    marker = part_number(doc.child_text("NextPartNumberMarker"))
                        .filter(|next| *next > marker)
                        .ok_or_else(|| {
                            bad_response(
                                &response,
                                "ListParts response did not advance the part marker",
                            )
                        })?;
                }
                None | Some("false") => return Ok(()),
                Some(_) => {
                    return Err(bad_response(
                        &response,
                        "ListParts response has invalid IsTruncated",
                    ))
                }
            }
        }
    }

    // None means HEAD confirmed the object is missing. An existing object that
    // cannot be verified blocks a replacement upload.
    fn find_completed(&self, token: &str, size: Option<u64>) -> Result<Option<String>, S3Error> {
        let mut call = Call::new("HEAD", Target::Object(self.key));
        call.cancel = Some(self.cancel);
        match self.client.upload_call(&call, self.opts, &mut |_| {}) {
            Ok(response) => {
                let is_ours = response.header(TOKEN_HEADER) == Some(token);
                let correct_size = size.is_none_or(|size| {
                    response
                        .header("content-length")
                        .and_then(|s| s.parse().ok())
                        == Some(size)
                });
                let etag = response
                    .header("etag")
                    .map(strip_quotes)
                    .filter(|tag| !tag.is_empty());
                etag.filter(|_| is_ours && correct_size)
                    .map(Some)
                    .ok_or_else(|| {
                        S3Error::new(
                            0,
                            "MultipartCompletionConflict",
                            "The current object could not be verified as this multipart upload. The upload checkpoint was retained.",
                        )
                    })
            }
            Err(e) if e.status == 404 => Ok(None),
            Err(e) if e.status == 403 && self.client.uses_session_provider() => {
                // Prefix-scoped S3 sessions can report a missing object as 403 on HEAD.
                let (objects, next) = self.client.list_objects_page_cancel(
                    self.key, 1, None, self.cancel,
                )?;
                if next.is_none() && objects.iter().all(|object| object.key != self.key) {
                    Ok(None)
                } else {
                    Err(e)
                }
            }
            Err(e) => Err(e),
        }
    }

    fn upload_parts(
        &self,
        source: &Path,
        id: &str,
        parts: &[&Part],
        progress: &mut dyn FnMut(u64),
        record: &mut dyn FnMut(&Part, String) -> Result<(), S3Error>,
    ) -> Result<(), S3Error> {
        let workers = self
            .opts
            .multipart_parallelism
            .clamp(1, MAX_PART_WORKERS)
            .min(parts.len());
        let streaming_progress =
            self.opts.multipart_checkpoint.is_none() && self.opts.multipart_parallelism <= 1;
        if workers <= 1 {
            for part in parts {
                let mut reported = 0;
                let etag = self.put_part(source, id, part, &mut |n| {
                    if streaming_progress {
                        let delta = n.min(part.len - reported);
                        reported += delta;
                        if delta > 0 {
                            progress(delta);
                        }
                    }
                })?;
                record(part, etag)?;
                if reported < part.len {
                    progress(part.len - reported);
                }
            }
            return Ok(());
        }

        let queue = Mutex::new(parts.iter().copied());
        let stop = AtomicBool::new(false);
        std::thread::scope(|scope| {
            let (sender, receiver) = mpsc::sync_channel(workers);
            for _ in 0..workers {
                let (sender, queue, stop) = (sender.clone(), &queue, &stop);
                scope.spawn(move || {
                    while !stop.load(Ordering::Relaxed) && !self.cancel.load(Ordering::Relaxed) {
                        let Some(part) = queue.lock().unwrap().next() else {
                            break;
                        };
                        let result = self.put_part(source, id, part, &mut |_| {});
                        if result.is_err() {
                            stop.store(true, Ordering::Relaxed);
                        }
                        if sender.send((part, result)).is_err() {
                            break;
                        }
                    }
                });
            }
            drop(sender);
            let mut failure = None;
            for (part, result) in receiver {
                match result.and_then(|etag| record(part, etag)) {
                    Ok(()) => progress(part.len),
                    Err(e) => {
                        stop.store(true, Ordering::Relaxed);
                        failure.get_or_insert(e);
                    }
                }
            }
            failure.map_or_else(|| check_cancel(Some(self.cancel)), Err)
        })
    }

    fn put_part(
        &self,
        source: &Path,
        id: &str,
        part: &Part,
        progress: &mut dyn FnMut(u64),
    ) -> Result<String, S3Error> {
        let body = PartBody { path: source, part };
        let mut call = Call::new("PUT", Target::Object(self.key))
            .q("partNumber", &part.number.to_string())
            .q("uploadId", id);
        call.cancel = Some(self.cancel);
        call.body = Some(&body);
        call.payload_hash = part.hash.as_ref().map(|hash| hex(hash));
        let response = self.client.upload_call(&call, self.opts, progress)?;
        response
            .header("etag")
            .filter(|tag| !strip_quotes(tag).is_empty())
            .map(str::to_owned)
            .ok_or_else(|| bad_response(&response, "UploadPart response without ETag"))
    }

    fn complete(&self, id: &str, etags: &[Option<String>]) -> Result<String, S3Error> {
        let mut body = String::from(
            "<CompleteMultipartUpload xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">",
        );
        for (index, etag) in etags.iter().enumerate() {
            let Some(etag) = etag else {
                return Err(S3Error::new(
                    0,
                    "MissingPart",
                    "Multipart upload ended with missing parts",
                ));
            };
            body.push_str(&format!(
                "<Part><PartNumber>{}</PartNumber><ETag>{}</ETag></Part>",
                index + 1,
                xml::escape(etag)
            ));
        }
        body.push_str("</CompleteMultipartUpload>");
        let body = BytesBody(body.as_bytes());
        let mut call = Call::new("POST", Target::Object(self.key))
            .q("uploadId", id)
            .h("content-type", "application/xml");
        call.cancel = Some(self.cancel);
        call.body = Some(&body);
        let response = self.client.upload_call(&call, self.opts, &mut |_| {})?;
        let doc = multipart_xml(&response, "CompleteMultipartUploadResult")?;
        doc.child_text("ETag")
            .map(strip_quotes)
            .filter(|tag| !tag.is_empty())
            .ok_or_else(|| bad_response(&response, "CompleteMultipartUpload response without ETag"))
    }
}

fn check_cancel(cancel: Option<&AtomicBool>) -> Result<(), S3Error> {
    if cancel.is_some_and(|flag| flag.load(Ordering::Relaxed)) {
        Err(S3Error::cancelled())
    } else {
        Ok(())
    }
}

fn part_number(text: Option<&str>) -> Option<usize> {
    text?
        .trim()
        .parse()
        .ok()
        .filter(|n| (1..=MAX_PARTS as usize).contains(n))
}

fn missing_upload(error: &S3Error) -> bool {
    error.code == "NoSuchUpload" || (error.status == 404 && error.code == "NotFound")
}

fn permission_denied(error: &S3Error) -> bool {
    matches!(error.code.as_str(), "AccessDenied" | "Forbidden")
}

fn multipart_xml(response: &Response, root: &str) -> Result<xml::Element, S3Error> {
    let doc = xml::parse(&response.body_text()).map_err(|e| bad_response(response, e))?;
    match doc.name.as_str() {
        name if name == root => Ok(doc),
        "Error" => Err(error_from_doc(response.status, &doc)),
        _ => Err(bad_response(response, format!("Expected {root} response"))),
    }
}

fn bad_response(response: &Response, message: impl Into<String>) -> S3Error {
    S3Error::new(response.status, "BadResponse", message)
}
