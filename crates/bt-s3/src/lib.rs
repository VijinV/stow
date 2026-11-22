//! From-scratch HTTP/1.1 + S3 client (AWS Signature V4). No third-party crates.
//!
//! TLS is pluggable through [`TlsConnector`] so this crate does not depend on a
//! particular TLS implementation.

mod client;
mod error;
pub mod http;
pub mod sigv4;
pub mod time;
pub mod xml;

pub use client::{BodySource, BytesBody, FileRange, ObjectInfo, S3Client, S3Config, UploadOptions};
pub use client::UploadBudget;
pub use client::{ObjectVersion, ObjectVersionsPage, VersionCursor};
pub use client::{CredentialProvider, RequestCredentials};
pub use error::S3Error;
pub use http::{NoTls, Stream, TlsConnector, Url};
