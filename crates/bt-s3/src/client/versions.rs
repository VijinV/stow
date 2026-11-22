//! Read-only S3 object version operations.
use super::{strip_quotes, Call, ObjectInfo, S3Client, Target};
use crate::{http::Response, xml, S3Error};
use std::fs::File;
use std::path::Path;
use std::sync::atomic::AtomicBool;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObjectVersion {
    pub object: ObjectInfo,
    pub version_id: String,
    pub is_latest: bool,
    pub is_delete_marker: bool,
}

/// Opaque pagination position. Reuse it with the same prefix.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VersionCursor {
    key: String,
    version_id: String,
}

impl VersionCursor {
    /// The object key at the pagination boundary.
    pub fn key(&self) -> &str {
        &self.key
    }
}

#[derive(Debug)]
pub struct ObjectVersionsPage {
    pub versions: Vec<ObjectVersion>,
    pub next: Option<VersionCursor>,
}

impl S3Client {
    /// Fetch one page, including delete markers in the order returned by S3.
    pub fn list_object_versions_page(
        &self,
        prefix: &str,
        max_keys: u32,
        cursor: Option<&VersionCursor>,
        cancel: &AtomicBool,
    ) -> Result<ObjectVersionsPage, S3Error> {
        let mut call = Call::new("GET", Target::Bucket)
            .q("versions", "")
            .q("encoding-type", "url")
            .q("max-keys", &max_keys.to_string());
        if !prefix.is_empty() {
            call = call.q("prefix", prefix);
        }
        if let Some(cursor) = cursor {
            call = call
                .q("key-marker", &cursor.key)
                .q("version-id-marker", &cursor.version_id);
        }
        call.cancel = Some(cancel);
        let response = self.call_simple(&call)?;
        let page = parse_page(&response.body)
            .map_err(|e| S3Error::new(response.status, "BadVersionListing", e))?;
        if page.next.is_some() && page.next.as_ref() == cursor {
            return Err(S3Error::new(
                response.status,
                "BadVersionListing",
                "S3 repeated the version listing cursor",
            ));
        }
        Ok(page)
    }

    /// Stream a specific version and return the user metadata from the same GET.
    pub fn get_object_version_to_file(
        &self,
        version: &ObjectVersion,
        dest: &Path,
        progress: &mut dyn FnMut(u64),
        cancel: &AtomicBool,
    ) -> Result<Vec<(String, String)>, S3Error> {
        if version.is_delete_marker || version.version_id.is_empty() {
            return Err(S3Error::new(
                0,
                "InvalidVersion",
                "Select a file version to download",
            ));
        }
        let response =
            self.download_to_file(&version.object.key, Some(version), dest, progress, cancel)?;
        Ok(response
            .headers
            .into_iter()
            .filter_map(|(name, value)| {
                name.to_ascii_lowercase()
                    .strip_prefix("x-amz-meta-")
                    .map(|key| (key.to_string(), value))
            })
            .collect())
    }
}

pub(super) fn confirm_download(
    version: &ObjectVersion,
    response: &Response,
    file: &File,
) -> Result<(), S3Error> {
    if response.status != 200
        || response.header("x-amz-version-id") != Some(&version.version_id)
        || response
            .header("x-amz-delete-marker")
            .is_some_and(|value| value.eq_ignore_ascii_case("true"))
    {
        return Err(S3Error::new(
            response.status,
            "VersionMismatch",
            "The storage service did not confirm the requested version",
        ));
    }
    // The null version can change while versioning is suspended.
    if file.metadata().map_err(|e| S3Error::local(&e))?.len() != version.object.size
        || (!version.object.etag.is_empty()
            && response.header("etag").map(strip_quotes).as_ref() != Some(&version.object.etag))
    {
        return Err(S3Error::new(response.status, "VersionMismatch", "The downloaded version does not match the listing. Refresh the version history and try again"));
    }
    Ok(())
}

fn parse_page(body: &[u8]) -> Result<ObjectVersionsPage, String> {
    let doc = xml::parse(std::str::from_utf8(body).map_err(|e| e.to_string())?)?;
    if doc.name != "ListVersionsResult" {
        return Err(format!(
            "Expected an S3 version listing, received {}",
            doc.name
        ));
    }
    let decode_key = match doc.child_text("EncodingType") {
        Some("url") => decode_url_key,
        None | Some("") => |key: &str| Ok(key.to_owned()),
        Some(value) => return Err(format!("Unsupported version listing encoding {value:?}")),
    };
    let mut versions = Vec::new();
    for entry in &doc.children {
        let is_delete_marker = match entry.name.as_str() {
            "Version" => false,
            "DeleteMarker" => true,
            _ => continue,
        };
        let size = if is_delete_marker {
            0
        } else {
            field(entry, "Size")?
                .trim()
                .parse()
                .map_err(|_| "Invalid version size")?
        };
        versions.push(ObjectVersion {
            object: ObjectInfo {
                key: decode_key(field(entry, "Key")?)?,
                size,
                etag: strip_quotes(entry.child_text("ETag").unwrap_or_default()),
                last_modified: entry
                    .child_text("LastModified")
                    .unwrap_or_default()
                    .to_owned(),
            },
            // S3 URL-encodes key fields only. Version IDs are opaque XML text.
            version_id: field(entry, "VersionId")?.to_owned(),
            is_latest: flag(entry, "IsLatest")?,
            is_delete_marker,
        });
    }
    let next = if flag(&doc, "IsTruncated")? {
        Some(VersionCursor {
            key: decode_key(field(&doc, "NextKeyMarker")?)?,
            version_id: field(&doc, "NextVersionIdMarker")?.to_owned(),
        })
    } else {
        None
    };
    Ok(ObjectVersionsPage { versions, next })
}

fn field<'a>(entry: &'a xml::Element, name: &str) -> Result<&'a str, String> {
    entry
        .child_text(name)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| format!("Missing {name} in S3 version listing"))
}

fn flag(entry: &xml::Element, name: &str) -> Result<bool, String> {
    match field(entry, name)?.trim() {
        "true" | "1" => Ok(true),
        "false" | "0" => Ok(false),
        _ => Err(format!("Invalid {name} in S3 version listing")),
    }
}

fn decode_url_key(key: &str) -> Result<String, String> {
    let mut decoded = Vec::with_capacity(key.len());
    let mut bytes = key.bytes();
    while let Some(byte) = bytes.next() {
        if byte == b'%' {
            let mut digit = || {
                bytes
                    .next()
                    .and_then(|b| char::from(b).to_digit(16))
                    .map(|n| n as u8)
                    .ok_or("Invalid percent encoding in S3 version listing")
            };
            let high = digit()?;
            decoded.push((high << 4) | digit()?);
        } else {
            decoded.push(byte);
        }
    }
    String::from_utf8(decoded).map_err(|_| "Invalid UTF-8 key in S3 version listing".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn version_listing_rejects_invalid_key_encoding_and_missing_markers() {
        let invalid_key = b"<ListVersionsResult><EncodingType>url</EncodingType>
            <IsTruncated>false</IsTruncated><DeleteMarker><Key>bad%XX</Key>
            <VersionId>marker</VersionId><IsLatest>true</IsLatest>
            </DeleteMarker></ListVersionsResult>";
        assert!(parse_page(invalid_key)
            .unwrap_err()
            .contains("Invalid percent encoding"));

        let missing_marker = b"<ListVersionsResult><IsTruncated>true</IsTruncated>
            <NextKeyMarker>key</NextKeyMarker></ListVersionsResult>";
        assert!(parse_page(missing_marker)
            .unwrap_err()
            .contains("NextVersionIdMarker"));

        let current_listing =
            b"<ListBucketResult><IsTruncated>false</IsTruncated></ListBucketResult>";
        assert!(parse_page(current_listing)
            .unwrap_err()
            .contains("Expected an S3 version listing"));
    }

    #[test]
    fn version_pages_preserve_opaque_ids_and_decode_key_markers_once() {
        use std::io::{BufRead, BufReader};
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let server = std::thread::spawn(move || {
            let pages = [
                (
                    "GET /bucket?encoding-type=url&max-keys=1&prefix=old%2F&versions= HTTP/1.1",
                    r#"<ListVersionsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
                    <IsTruncated>true</IsTruncated><EncodingType>url</EncodingType>
                    <NextKeyMarker>old%2Fcaf%C3%A9+%2520.txt</NextKeyMarker>
                    <NextVersionIdMarker>delete+/=%2F&amp;#</NextVersionIdMarker>
                    <DeleteMarker><Key>old%2Fcaf%C3%A9+%2520.txt</Key>
                    <VersionId>delete+/=%2F&amp;#</VersionId><IsLatest>true</IsLatest>
                    <LastModified>2026-11-22T12:00:00Z</LastModified></DeleteMarker>
                    </ListVersionsResult>"#,
                ),
                (
                    "GET /bucket?encoding-type=url&key-marker=old%2Fcaf%C3%A9%2B%2520.txt&max-keys=1&prefix=old%2F&version-id-marker=delete%2B%2F%3D%252F%26%23&versions= HTTP/1.1",
                    r#"<ListVersionsResult><IsTruncated>false</IsTruncated><EncodingType>url</EncodingType>
                    <Version><Key>old%2Fcaf%C3%A9%2B%2520.txt</Key><VersionId>null</VersionId>
                    <IsLatest>false</IsLatest><LastModified>2026-11-21T12:00:00Z</LastModified>
                    <ETag>&quot;etag&quot;</ETag><Size>42</Size></Version></ListVersionsResult>"#,
                ),
            ];
            for (request, body) in pages {
                let (mut stream, _) = listener.accept().unwrap();
                let mut reader = BufReader::new(&mut stream);
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                assert_eq!(line.trim_end(), request);
                loop {
                    line.clear();
                    if reader.read_line(&mut line).unwrap() == 0 || line == "\r\n" {
                        break;
                    }
                }
                write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{body}",
                    body.len()
                )
                .unwrap();
            }
        });
        let c = S3Client::new(
            crate::S3Config {
                endpoint,
                bucket: "bucket".into(),
                path_style: true,
                ..Default::default()
            },
            std::sync::Arc::new(crate::NoTls),
        );
        let first = c
            .list_object_versions_page("old/", 1, None, &AtomicBool::new(false))
            .unwrap();
        assert_eq!(first.versions[0].object.key, "old/café+%20.txt");
        assert!(first.versions[0].is_latest && first.versions[0].is_delete_marker);
        assert_eq!(first.versions[0].version_id, "delete+/=%2F&#");
        let second = c
            .list_object_versions_page("old/", 1, first.next.as_ref(), &AtomicBool::new(false))
            .unwrap();
        assert_eq!(second.versions[0].object.key, first.versions[0].object.key);
        assert_eq!(second.versions[0].version_id, "null");
        assert_eq!(second.versions[0].object.size, 42);
        assert!(!second.versions[0].is_latest && !second.versions[0].is_delete_marker);
        assert!(second.next.is_none());
        server.join().unwrap();
    }
}
