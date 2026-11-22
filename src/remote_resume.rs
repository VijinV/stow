//! Private Stow resume storage and retention of the original encryption envelope.
use bt_s3::UploadOptions;
use bt_tls::crypto::{hmac::HmacSha256, sha256::Sha256, util::hex};
use std::fs::{self, DirBuilder, File, Metadata, OpenOptions, TryLockError};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

pub(super) struct ResumeSlot {
    directory: PathBuf,
    _lock: File,
}

impl ResumeSlot {
    pub fn lock(root: &Path, destination: &str, cancel: &AtomicBool) -> Result<Self, String> {
        cancelled(cancel)?;
        private_dir(root).map_err(resume_error)?;
        // Bounded set of lock files. Keep the file around so waiters always
        // lock the same inode. The OS releases the lock after a process exits.
        let mut open = OpenOptions::new();
        open.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            open.mode(0o600);
        }
        let lock = open
            .open(root.join(format!("lock-{}", &destination[..2])))
            .map_err(resume_error)?;
        loop {
            cancelled(cancel)?;
            match lock.try_lock() {
                Ok(()) => break,
                Err(TryLockError::WouldBlock) => std::thread::sleep(Duration::from_millis(50)),
                Err(TryLockError::Error(e)) => return Err(resume_error(e)),
            }
        }
        Ok(Self {
            directory: root.join(destination),
            _lock: lock,
        })
    }

    pub fn checkpoint(&self, multipart: bool) -> Result<PathBuf, String> {
        if multipart {
            private_dir(&self.directory).map_err(resume_error)?;
        }
        Ok(self.directory.join("multipart"))
    }

    pub fn encrypted_source(
        &self,
        source: &Path,
        recovery_key: &str,
        options: &UploadOptions,
        cancel: &AtomicBool,
    ) -> Result<(PathBuf, u64), String> {
        let key = crate::file_crypto::validate_key(recovery_key)?;
        let original = SourceFingerprint::read(source, &key, cancel)?;
        let payload = self.directory.join("ciphertext");
        let identity = self.directory.join("ciphertext-identity");
        let staging = self.directory.join("encryption-staging");

        // A hard shutdown during envelope creation can leave an unpublished
        // ciphertext in staging. The destination lock makes cleanup exclusive.
        remove_staging(&staging).map_err(resume_error)?;
        match fs::read_to_string(&identity) {
            Ok(contents) => {
                let verified = match contents.split_once('\n') {
                    Some((saved_source, saved_ciphertext)) if saved_source == original.digest => {
                        match File::open(&payload) {
                            Ok(mut file) => {
                                let mut hash = Sha256::new();
                                for_chunks(&mut file, cancel, |data| hash.update(data))?;
                                hex(&hash.finalize()) == saved_ciphertext.trim_end()
                            }
                            Err(e) if e.kind() == io::ErrorKind::NotFound => false,
                            Err(e) => return Err(resume_error(e)),
                        }
                    }
                    _ => false,
                };
                if verified {
                    return Ok((payload, original.size));
                }
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(resume_error(e)),
        }

        self.clear_ciphertext().map_err(resume_error)?;
        private_dir(&staging).map_err(resume_error)?;
        let staged = staging.join("envelope");
        let result = (|| {
            crate::file_crypto::encrypt_file_cancel(source, &staged, recovery_key, cancel)?;
            let after = SourceFingerprint::read(source, &key, cancel)?;
            if original != after {
                return Err("Source file changed while preparing encrypted upload".into());
            }
            let mut file = File::open(&staged).map_err(resume_error)?;
            let size = file.metadata().map_err(resume_error)?.len();
            let saved = if options.uses_multipart(size) {
                let mut hash = Sha256::new();
                for_chunks(&mut file, cancel, |data| hash.update(data))?;
                Some(format!("{}\n{}\n", original.digest, hex(&hash.finalize())))
            } else {
                None
            };
            drop(file);
            cancelled(cancel)?;
            fs::rename(&staged, &payload).map_err(resume_error)?;
            if let Some(saved) = saved {
                crate::paths::write_private(&identity, saved.as_bytes()).map_err(resume_error)?;
                #[cfg(unix)]
                File::open(&self.directory)
                    .and_then(|dir| dir.sync_all())
                    .map_err(resume_error)?;
            }
            Ok((payload, original.size))
        })();
        let _ = remove_staging(&staging);
        result
    }

    pub fn clear_ciphertext(&self) -> io::Result<()> {
        for name in [
            "ciphertext-identity",
            "ciphertext-identity.tmp",
            "ciphertext",
        ] {
            match fs::remove_file(self.directory.join(name)) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(e),
            }
        }
        remove_staging(&self.directory.join("encryption-staging"))
    }

    pub fn clear_completed(&self) -> Result<(), String> {
        match fs::remove_file(self.directory.join("multipart")) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(resume_error(e)),
        }
        self.clear_ciphertext().map_err(resume_error)
    }
}

impl Drop for ResumeSlot {
    fn drop(&mut self) {
        let _ = fs::remove_dir(&self.directory);
    }
}

fn private_dir(path: &Path) -> io::Result<()> {
    let mut builder = DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(path)
}

fn remove_staging(path: &Path) -> io::Result<()> {
    match fs::remove_dir_all(path) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        other => other,
    }
}

fn resume_error(error: io::Error) -> String {
    format!("Could not access upload resume data: {error}")
}

fn cancelled(cancel: &AtomicBool) -> Result<(), String> {
    if cancel.load(Ordering::Relaxed) {
        Err("Cancelled".into())
    } else {
        Ok(())
    }
}

fn for_chunks(
    file: &mut File,
    cancel: &AtomicBool,
    mut visit: impl FnMut(&[u8]),
) -> Result<(), String> {
    let mut buf = vec![0; 256 * 1024];
    loop {
        cancelled(cancel)?;
        let size = file.read(&mut buf).map_err(resume_error)?;
        if size == 0 {
            return Ok(());
        }
        visit(&buf[..size]);
    }
}

#[derive(PartialEq, Eq)]
struct SourceFingerprint {
    digest: String,
    stamp: SourceStamp,
    size: u64,
}

#[derive(PartialEq, Eq)]
struct SourceStamp {
    modified: Option<std::time::SystemTime>,
    #[cfg(unix)]
    unix_identity: (u64, u64, i64, i64),
}

impl SourceStamp {
    fn new(meta: &Metadata) -> Self {
        #[cfg(unix)]
        use std::os::unix::fs::MetadataExt;
        Self {
            modified: meta.modified().ok(),
            #[cfg(unix)]
            unix_identity: (meta.dev(), meta.ino(), meta.ctime(), meta.ctime_nsec()),
        }
    }
}

impl SourceFingerprint {
    fn read(path: &Path, key: &[u8; 32], cancel: &AtomicBool) -> Result<Self, String> {
        let mut file = File::open(path).map_err(resume_error)?;
        let metadata = file.metadata().map_err(resume_error)?;
        let stamp = SourceStamp::new(&metadata);
        let mut hash = HmacSha256::new(key);
        hash.update(b"Stow encrypted multipart source v1\0");
        let mut size = 0;
        for_chunks(&mut file, cancel, |data| {
            size += data.len() as u64;
            hash.update(data);
        })?;
        if size != metadata.len()
            || stamp != SourceStamp::new(&fs::metadata(path).map_err(resume_error)?)
        {
            return Err("Source file changed while checking encrypted upload".into());
        }
        Ok(Self {
            digest: hex(&hash.finalize()),
            stamp,
            size,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypted_restarts_reuse_exact_ciphertext_and_reject_changed_source() {
        let key = crate::file_crypto::generate_key().unwrap();
        let root = std::env::temp_dir().join(format!("stow-resume-test-{key}"));
        fs::create_dir(&root).unwrap();
        let source = root.join("source");
        let resume = root.join("resume");
        let original = vec![0xab; 5 << 20];
        fs::write(&source, &original).unwrap();
        let cancel = AtomicBool::new(false);
        let id = "4a".repeat(32);
        let options = UploadOptions {
            multipart_threshold: 5 << 20,
            ..Default::default()
        };
        let first = {
            let slot = ResumeSlot::lock(&resume, &id, &cancel).unwrap();
            let (payload, size) = slot
                .encrypted_source(&source, &key, &options, &cancel)
                .unwrap();
            assert_eq!(size, original.len() as u64);
            fs::read(payload).unwrap()
        };
        let slot = ResumeSlot::lock(&resume, &id, &cancel).unwrap();
        let (payload, _) = slot
            .encrypted_source(&source, &key, &options, &cancel)
            .unwrap();
        assert_eq!(fs::read(&payload).unwrap(), first);
        let changed = vec![0xcd; original.len()];
        fs::write(&source, &changed).unwrap();
        let (payload, _) = slot
            .encrypted_source(&source, &key, &options, &cancel)
            .unwrap();
        assert_ne!(fs::read(&payload).unwrap(), first);
        let restored = root.join("restored");
        assert!(crate::file_crypto::decrypt_file(&payload, &restored, &key).unwrap());
        assert_eq!(fs::read(&restored).unwrap(), changed);
        drop(slot);
        fs::remove_dir_all(root).unwrap();
    }
}
