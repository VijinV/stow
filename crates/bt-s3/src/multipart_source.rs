//! Part sizing, content fingerprints, and verified streaming request bodies.
use super::{
    check_cancel, fs, hex, io, AtomicBool, Body, File, Path, Read, S3Error, Seek, SeekFrom, Sha256,
    MAX_PARTS,
};

const MIB: u64 = 1 << 20;
const MAX_PART_SIZE: u64 = 5 << 30;
const SOURCE_CHANGED: &str = "source file changed during multipart upload";

pub(super) struct Part {
    pub number: usize,
    offset: u64,
    pub len: u64,
    pub hash: Option<[u8; 32]>,
}

pub(super) struct PartPlan {
    size: u64,
    part_size: u64,
    pub parts: Vec<Part>,
    source_metadata: Option<fs::Metadata>,
}

impl PartPlan {
    pub fn new(size: u64, part_size: u64) -> Result<Self, S3Error> {
        let min_for_count = size.div_ceil(MAX_PARTS);
        let mut part_size = part_size.clamp(5 * MIB, MAX_PART_SIZE);
        if part_size < min_for_count {
            part_size = min_for_count.div_ceil(MIB) * MIB;
        }
        if part_size > MAX_PART_SIZE {
            return Err(S3Error::new(
                0,
                "EntityTooLarge",
                "Object exceeds S3 multipart size limits",
            ));
        }
        let parts = (0..size.div_ceil(part_size))
            .map(|index| {
                let offset = index * part_size;
                Part {
                    number: index as usize + 1,
                    offset,
                    len: part_size.min(size - offset),
                    hash: None,
                }
            })
            .collect();
        Ok(Self {
            size,
            part_size,
            parts,
            source_metadata: None,
        })
    }

    pub fn fingerprint(
        &mut self,
        source: &Path,
        headers: &[(String, String)],
        cancel: &AtomicBool,
    ) -> Result<String, S3Error> {
        check_cancel(Some(cancel))?;
        let mut fingerprint = Sha256::new();
        fingerprint.update(&self.size.to_be_bytes());
        fingerprint.update(&self.part_size.to_be_bytes());
        for (name, value) in headers {
            hash_field(&mut fingerprint, name.as_bytes());
            hash_field(&mut fingerprint, value.as_bytes());
        }

        let mut input = File::open(source).map_err(|e| S3Error::local(&e))?;
        self.source_metadata = Some(input.metadata().map_err(|e| S3Error::local(&e))?);
        let mut buf = vec![0; 256 * 1024];
        for part in &mut self.parts {
            let mut hash = Sha256::new();
            let mut remaining = part.len;
            while remaining > 0 {
                check_cancel(Some(cancel))?;
                let len = remaining.min(buf.len() as u64) as usize;
                input
                    .read_exact(&mut buf[..len])
                    .map_err(|e| S3Error::local(&e))?;
                hash.update(&buf[..len]);
                remaining -= len as u64;
            }
            let hash = hash.finalize();
            fingerprint.update(&hash);
            part.hash = Some(hash);
        }
        if input.read(&mut [0]).map_err(|e| S3Error::local(&e))? != 0 {
            return Err(S3Error::new(0, "SourceChanged", SOURCE_CHANGED));
        }
        self.check_source(source)?;
        Ok(hex(&fingerprint.finalize()))
    }

    pub fn check_source(&self, source: &Path) -> Result<(), S3Error> {
        if let Some(initial) = &self.source_metadata {
            let current = fs::metadata(source).map_err(|e| S3Error::local(&e))?;
            if !same_source_revision(initial, &current) {
                return Err(S3Error::new(0, "SourceChanged", SOURCE_CHANGED));
            }
        }
        Ok(())
    }
}

fn same_source_revision(a: &fs::Metadata, b: &fs::Metadata) -> bool {
    if a.len() != b.len() || a.modified().ok() != b.modified().ok() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        (a.dev(), a.ino(), a.ctime(), a.ctime_nsec())
            == (b.dev(), b.ino(), b.ctime(), b.ctime_nsec())
    }
    #[cfg(not(unix))]
    true
}

pub(super) fn hash_field(hash: &mut Sha256, value: &[u8]) {
    hash.update(&(value.len() as u64).to_be_bytes());
    hash.update(value);
}

pub(super) struct PartBody<'a> {
    pub path: &'a Path,
    pub part: &'a Part,
}

impl Body for PartBody<'_> {
    fn len(&self) -> u64 {
        self.part.len
    }

    fn open(&self) -> io::Result<Box<dyn Read + '_>> {
        let open_at_offset = || {
            let mut file = File::open(self.path)?;
            file.seek(SeekFrom::Start(self.part.offset))?;
            Ok(file.take(self.part.len))
        };
        match self.part.hash {
            Some(expected) => Ok(Box::new(CheckedPart {
                reader: open_at_offset().map_err(interrupt_write)?,
                hash: Sha256::new(),
                expected,
            })),
            None => Ok(Box::new(open_at_offset()?)),
        }
    }
}

#[derive(Debug)]
pub(in crate::client) struct PartReadError(io::Error);

impl std::fmt::Display for PartReadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.0, f)
    }
}

impl std::error::Error for PartReadError {}

fn interrupt_write(error: io::Error) -> io::Error {
    // End the HTTP exchange immediately. The server may still be waiting
    // for the remaining request body and have no response to read.
    io::Error::new(io::ErrorKind::Interrupted, PartReadError(error))
}

struct CheckedPart {
    reader: io::Take<File>,
    hash: Sha256,
    expected: [u8; 32],
}

impl Read for CheckedPart {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.reader.limit() == 0 || buf.is_empty() {
            return Ok(0);
        }
        let n = self.reader.read(buf).map_err(interrupt_write)?;
        self.hash.update(&buf[..n]);
        if n == 0
            || (self.reader.limit() == 0
                && std::mem::take(&mut self.hash).finalize() != self.expected)
        {
            return Err(interrupt_write(io::Error::new(
                io::ErrorKind::InvalidData,
                SOURCE_CHANGED,
            )));
        }
        Ok(n)
    }
}
