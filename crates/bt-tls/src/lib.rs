//! From-scratch cryptography and a TLS 1.3 client. No third-party crates:
//! only `std` and operating-system APIs (random numbers, root certificates).
pub mod crypto;
pub mod der;
pub mod roots;
pub mod tls;
pub mod x509;

pub use roots::RootStore;
pub use tls::TlsStream;
