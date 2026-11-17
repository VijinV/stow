//! Versioned streaming file envelope. Filenames remain visible in object keys.
use bt_tls::crypto::{chacha20poly1305::ChaCha20Poly1305, hash::HashAlg, hkdf, random, util};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
const MAGIC: &[u8; 8] = b"BTENC001";
const CHUNK: usize = 64 * 1024;
const HEADER: usize = 40; // magic + random 256-bit salt

pub fn generate_key() -> Result<String, String> {
    Ok(util::hex(
        &random::array::<32>().map_err(|e| e.to_string())?,
    ))
}
pub fn validate_key(key: &str) -> Result<[u8; 32], String> {
    util::unhex(key.trim())
        .and_then(|v| v.try_into().ok())
        .ok_or_else(|| "Recovery key must contain exactly 64 hexadecimal characters.".into())
}
pub(crate) struct TempPath(pub PathBuf);
impl Drop for TempPath {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}
pub(crate) fn private_temp(parent: &Path) -> Result<(TempPath, File), String> {
    for _ in 0..10 {
        let path = parent.join(format!(".bt-{}", generate_key()?));
        let mut opts = OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        match opts.open(&path) {
            Ok(f) => return Ok((TempPath(path), f)),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e.to_string()),
        }
    }
    Err("Could not create private temporary file.".into())
}
fn cipher(key: &[u8; 32], header: &[u8]) -> ChaCha20Poly1305 {
    let prk = hkdf::extract(HashAlg::Sha256, &header[8..], key);
    let key: [u8; 32] = hkdf::expand(HashAlg::Sha256, &prk, b"BackupTaker file envelope v1", 32)
        .try_into()
        .unwrap();
    ChaCha20Poly1305::new(&key)
}
fn framing(header: &[u8], index: u64, length: u32) -> ([u8; 12], Vec<u8>) {
    let mut nonce = [0; 12];
    nonce[4..].copy_from_slice(&index.to_be_bytes());
    let mut aad = header.to_vec();
    aad.extend_from_slice(&index.to_be_bytes());
    aad.extend_from_slice(&length.to_be_bytes());
    (nonce, aad)
}
fn check_cancel(cancel: &AtomicBool) -> Result<(), String> {
    if cancel.load(Ordering::Relaxed) {
        Err("Cancelled".into())
    } else {
        Ok(())
    }
}
fn publish(temp: &TempPath, file: File, dest: &Path, cancel: &AtomicBool) -> Result<(), String> {
    check_cancel(cancel)?;
    file.sync_all().map_err(|e| e.to_string())?;
    drop(file);
    check_cancel(cancel)?;
    #[cfg(windows)]
    if dest.exists() {
        fs::remove_file(dest).map_err(|e| e.to_string())?;
    }
    fs::rename(&temp.0, dest).map_err(|e| e.to_string())
}
fn parent(path: &Path) -> &Path {
    path.parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."))
}
pub fn encrypt_file(source: &Path, dest: &Path, key_hex: &str) -> Result<(), String> {
    encrypt_file_cancel(source, dest, key_hex, &AtomicBool::new(false))
}
pub fn encrypt_file_cancel(
    source: &Path,
    dest: &Path,
    key_hex: &str,
    cancel: &AtomicBool,
) -> Result<(), String> {
    encrypt_impl(source, dest, key_hex, cancel, &mut || {})
}
fn encrypt_impl(
    source: &Path,
    dest: &Path,
    key_hex: &str,
    cancel: &AtomicBool,
    chunk_done: &mut dyn FnMut(),
) -> Result<(), String> {
    check_cancel(cancel)?;
    let key = validate_key(key_hex)?;
    let mut input = File::open(source).map_err(|e| e.to_string())?;
    let (temp, mut out) = private_temp(parent(dest))?;
    let mut header = MAGIC.to_vec();
    header.extend_from_slice(&random::array::<32>().map_err(|e| e.to_string())?);
    out.write_all(&header).map_err(|e| e.to_string())?;
    let cipher = cipher(&key, &header);
    let mut index = 0u64;
    loop {
        check_cancel(cancel)?;
        let mut data = vec![0; CHUNK];
        let mut n = 0;
        while n < CHUNK {
            check_cancel(cancel)?;
            let got = input.read(&mut data[n..]).map_err(|e| e.to_string())?;
            if got == 0 {
                break;
            }
            n += got;
        }
        data.truncate(n);
        let (nonce, aad) = framing(&header, index, n as u32);
        let tag = cipher.seal(&nonce, &aad, &mut data);
        out.write_all(&(n as u32).to_be_bytes())
            .and_then(|_| out.write_all(&data))
            .and_then(|_| out.write_all(&tag))
            .map_err(|e| e.to_string())?;
        chunk_done();
        if n == 0 {
            break;
        } // authenticated final empty frame is mandatory
        index = index.checked_add(1).ok_or("File is too large")?;
    }
    publish(&temp, out, dest, cancel)
}
pub fn is_encrypted_file(path: &Path) -> Result<bool, String> {
    let mut input = File::open(path).map_err(|e| e.to_string())?;
    let mut magic = [0; 8];
    let n = input.read(&mut magic).map_err(|e| e.to_string())?;
    // Reserve the versioned envelope family and reject single-byte damaged magic.
    // Arbitrary header destruction is indistinguishable from a legacy plaintext file;
    // callers with authenticated external metadata must also require this marker.
    Ok(n == MAGIC.len()
        && (magic.starts_with(b"BTENC")
            || magic
                .iter()
                .zip(MAGIC.iter())
                .filter(|(a, b)| a != b)
                .count()
                <= 1))
}
pub fn decrypt_file(source: &Path, dest: &Path, key_hex: &str) -> Result<bool, String> {
    decrypt_file_cancel(source, dest, key_hex, &AtomicBool::new(false))
}
pub fn decrypt_file_cancel(
    source: &Path,
    dest: &Path,
    key_hex: &str,
    cancel: &AtomicBool,
) -> Result<bool, String> {
    decrypt_impl(source, dest, key_hex, cancel, &mut || {})
}
fn decrypt_impl(
    source: &Path,
    dest: &Path,
    key_hex: &str,
    cancel: &AtomicBool,
    chunk_done: &mut dyn FnMut(),
) -> Result<bool, String> {
    check_cancel(cancel)?;
    if !is_encrypted_file(source)? {
        let mut input = File::open(source).map_err(|e| e.to_string())?;
        let (temp, mut out) = private_temp(parent(dest))?;
        let mut buffer = [0u8; CHUNK];
        loop {
            check_cancel(cancel)?;
            let count = input.read(&mut buffer).map_err(|e| e.to_string())?;
            if count == 0 {
                break;
            }
            out.write_all(&buffer[..count]).map_err(|e| e.to_string())?;
            chunk_done();
        }
        publish(&temp, out, dest, cancel)?;
        return Ok(false);
    }
    let key = validate_key(key_hex)?;
    let mut input = File::open(source).map_err(|e| e.to_string())?;
    let mut header = [0; HEADER];
    input
        .read_exact(&mut header)
        .map_err(|_| "Truncated encrypted header")?;
    if &header[..8] != MAGIC {
        return Err("Damaged or unsupported encrypted file header".into());
    }
    let cipher = cipher(&key, &header);
    let (temp, mut out) = private_temp(parent(dest))?;
    let mut index = 0u64;
    loop {
        check_cancel(cancel)?;
        let mut len = [0; 4];
        input
            .read_exact(&mut len)
            .map_err(|_| "Truncated encrypted file")?;
        let len = u32::from_be_bytes(len);
        if len as usize > CHUNK {
            return Err("Invalid encrypted chunk size".into());
        }
        let mut data = vec![0; len as usize];
        let mut tag = [0; 16];
        input
            .read_exact(&mut data)
            .and_then(|_| input.read_exact(&mut tag))
            .map_err(|_| "Truncated encrypted chunk")?;
        let (nonce, aad) = framing(&header, index, len);
        if !cipher.open(&nonce, &aad, &mut data, &tag) {
            return Err("File authentication failed: wrong recovery key or damaged backup.".into());
        }
        if len == 0 {
            let mut extra = [0; 1];
            if input.read(&mut extra).map_err(|e| e.to_string())? != 0 {
                return Err("Unexpected data after encrypted file".into());
            }
            break;
        }
        out.write_all(&data).map_err(|e| e.to_string())?;
        chunk_done();
        index = index.checked_add(1).ok_or("File is too large")?;
    }
    publish(&temp, out, dest, cancel)?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    fn dir() -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!("bt-crypto-test-{}", generate_key().unwrap()));
        fs::create_dir(&p).unwrap();
        p
    }
    #[test]
    fn cancellation_preserves_destination_and_cleans_partial_files() {
        use std::sync::atomic::{AtomicBool, Ordering};
        let d = dir();
        let key = generate_key().unwrap();
        fs::write(d.join("in"), vec![42; CHUNK * 3]).unwrap();
        fs::write(d.join("out"), b"keep").unwrap();
        encrypt_file(&d.join("in"), &d.join("enc"), &key).unwrap();
        let expected = fs::read_dir(&d).unwrap().count();
        let cancel = AtomicBool::new(true);
        assert!(encrypt_file_cancel(&d.join("in"), &d.join("out"), &key, &cancel).is_err());
        assert!(decrypt_file_cancel(&d.join("enc"), &d.join("out"), &key, &cancel).is_err());
        for plain in [true, false] {
            cancel.store(false, Ordering::Relaxed);
            let source = d.join(if plain { "in" } else { "enc" });
            let mut chunks = 0;
            let mut stop = || {
                chunks += 1;
                cancel.store(true, Ordering::Relaxed);
            };
            assert!(decrypt_impl(&source, &d.join("out"), &key, &cancel, &mut stop).is_err());
            assert_eq!(chunks, 1);
            assert_eq!(fs::read(d.join("out")).unwrap(), b"keep");
            assert_eq!(fs::read_dir(&d).unwrap().count(), expected);
        }
        cancel.store(false, Ordering::Relaxed);
        let mut chunks = 0;
        assert!(
            encrypt_impl(&d.join("in"), &d.join("out"), &key, &cancel, &mut || {
                chunks += 1;
                cancel.store(true, Ordering::Relaxed);
            })
            .is_err()
        );
        assert_eq!(chunks, 1);
        assert_eq!(fs::read(d.join("out")).unwrap(), b"keep");
        assert_eq!(fs::read_dir(&d).unwrap().count(), expected);
        fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn envelope_roundtrips_empty_and_multiple_chunks() {
        let d = dir();
        let key = generate_key().unwrap();
        for n in [0, 1, 180_001] {
            let data: Vec<_> = (0..n).map(|i| (i % 251) as u8).collect();
            fs::write(d.join("in"), &data).unwrap();
            encrypt_file(&d.join("in"), &d.join("encrypted"), &key).unwrap();
            assert!(is_encrypted_file(&d.join("encrypted")).unwrap());
            assert!(decrypt_file(&d.join("encrypted"), &d.join("out"), &key).unwrap());
            assert_eq!(fs::read(d.join("out")).unwrap(), data);
        }
        fs::remove_dir_all(d).unwrap();
    }
    #[test]
    fn rejects_corruption_without_publishing_plaintext() {
        let d = dir();
        let key = generate_key().unwrap();
        fs::write(d.join("in"), vec![42; 150_000]).unwrap();
        encrypt_file(&d.join("in"), &d.join("enc"), &key).unwrap();
        let original = fs::read(d.join("enc")).unwrap();
        for case in 0..6 {
            let mut damaged = original.clone();
            match case {
                0 => damaged[60] ^= 1,
                1 => {
                    damaged.pop();
                }
                2 => damaged.push(0),
                3 => damaged[10] ^= 1,
                5 => damaged[0] ^= 1,
                _ => {}
            }
            fs::write(d.join("bad"), damaged).unwrap();
            fs::write(d.join("out"), b"keep").unwrap();
            let k = if case == 4 {
                generate_key().unwrap()
            } else {
                key.clone()
            };
            assert!(
                decrypt_file(&d.join("bad"), &d.join("out"), &k).is_err(),
                "case {case}"
            );
            assert_eq!(fs::read(d.join("out")).unwrap(), b"keep");
        }
        fs::remove_dir_all(d).unwrap();
    }
    #[test]
    fn plaintext_compatibility_and_invalid_key() {
        let d = dir();
        fs::write(d.join("in"), b"plain").unwrap();
        assert!(!decrypt_file(&d.join("in"), &d.join("out"), "").unwrap());
        assert_eq!(fs::read(d.join("out")).unwrap(), b"plain");
        assert!(encrypt_file(&d.join("in"), &d.join("enc"), "bad").is_err());
        fs::remove_dir_all(d).unwrap();
    }
}
