use super::*;
use bt_tls::crypto::util::unhex;
use std::collections::BTreeMap;
use std::fs::OpenOptions;

// Written by the caller thread only. The header is published atomically before
// any part is sent, and each acknowledged part record is synced before reuse.
pub(super) struct Checkpoint {
    pub destination: String,
    pub fingerprint: String,
    pub token: String,
    pub upload_id: String,
    pub etags: BTreeMap<usize, String>,
    pub completing: bool,
    valid_len: u64,
}

impl Checkpoint {
    pub fn new(destination: String, fingerprint: String, token: String, upload_id: String) -> Self {
        Self {
            destination,
            fingerprint,
            token,
            upload_id,
            etags: BTreeMap::new(),
            completing: false,
            valid_len: 0,
        }
    }

    pub fn load(path: &Path) -> Result<Option<Self>, S3Error> {
        let contents = match fs::read_to_string(path) {
            Ok(contents) => contents,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(S3Error::local(&e)),
        };
        // A crash can cut off an append mid-record. Ignore that record and
        // truncate it before appending again.
        let end = contents.rfind('\n').map_or(0, |i| i + 1);
        let mut lines = contents[..end].lines();
        let invalid = || S3Error::new(0, "InvalidCheckpoint", "Invalid multipart checkpoint");
        if lines.next() != Some("stow-multipart-v1") {
            return Err(invalid());
        }
        let mut digest = || {
            lines
                .next()
                .filter(|s| s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit()))
                .map(str::to_owned)
                .ok_or_else(invalid)
        };
        let destination = digest()?;
        let fingerprint = digest()?;
        let token = digest()?;
        let upload_id = lines.next().and_then(decode).ok_or_else(invalid)?;
        let mut checkpoint = Self::new(destination, fingerprint, token, upload_id);
        checkpoint.valid_len = end as u64;
        for line in lines {
            if line == "complete" {
                checkpoint.completing = true;
            } else {
                let (part, etag) = line.split_once(' ').ok_or_else(invalid)?;
                let part = part
                    .parse::<usize>()
                    .ok()
                    .filter(|n| (1..=10_000).contains(n))
                    .ok_or_else(invalid)?;
                checkpoint
                    .etags
                    .insert(part, decode(etag).ok_or_else(invalid)?);
            }
        }
        Ok(Some(checkpoint))
    }

    pub fn publish(&mut self, path: &Path) -> Result<(), S3Error> {
        let mut temp = path.as_os_str().to_owned();
        temp.push(".pending");
        let temp = PathBuf::from(temp);
        let result = (|| -> io::Result<()> {
            let mut opts = OpenOptions::new();
            opts.write(true).create(true).truncate(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                opts.mode(0o600);
            }
            let mut file = opts.open(&temp)?;
            let contents = format!(
                "stow-multipart-v1\n{}\n{}\n{}\n{}\n",
                self.destination,
                self.fingerprint,
                self.token,
                hex(self.upload_id.as_bytes())
            );
            file.write_all(contents.as_bytes())?;
            file.sync_all()?;
            drop(file);
            fs::rename(&temp, path)?;
            #[cfg(unix)]
            if let Some(parent) = path.parent() {
                let dir = if parent.as_os_str().is_empty() {
                    Path::new(".")
                } else {
                    parent
                };
                File::open(dir)?.sync_all()?;
            }
            self.valid_len = contents.len() as u64;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temp);
        }
        result.map_err(|e| S3Error::local(&e))
    }

    pub fn record_part(&mut self, path: &Path, number: usize, etag: &str) -> Result<(), S3Error> {
        self.append(path, &format!("{number} {}\n", hex(etag.as_bytes())))
    }

    pub fn mark_completing(&mut self, path: &Path) -> Result<(), S3Error> {
        if !self.completing {
            self.append(path, "complete\n")?;
            self.completing = true;
        }
        Ok(())
    }

    fn append(&mut self, path: &Path, record: &str) -> Result<(), S3Error> {
        let result = (|| -> io::Result<()> {
            let mut file = OpenOptions::new().write(true).open(path)?;
            file.set_len(self.valid_len)?;
            file.seek(SeekFrom::Start(self.valid_len))?;
            file.write_all(record.as_bytes())?;
            file.sync_data()
        })();
        result.map_err(|e| S3Error::local(&e))?;
        self.valid_len += record.len() as u64;
        Ok(())
    }
}

fn decode(value: &str) -> Option<String> {
    let decoded = String::from_utf8(unhex(value)?).ok()?;
    (!decoded.is_empty()).then_some(decoded)
}

pub(super) fn remove(path: &Path) -> Result<(), S3Error> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(S3Error::local(&e)),
    }
}
