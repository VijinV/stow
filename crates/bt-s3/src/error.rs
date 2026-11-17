use std::fmt;

/// Error from an S3 operation. `status` is 0 for network/local errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct S3Error {
    pub status: u16,
    pub code: String,
    pub message: String,
}

impl S3Error {
    pub fn new(status: u16, code: &str, message: impl Into<String>) -> S3Error {
        S3Error { status, code: code.to_string(), message: message.into() }
    }
    pub fn network(e: &std::io::Error) -> S3Error {
        S3Error::new(0, "NetworkError", e.to_string())
    }
    pub fn local(e: &std::io::Error) -> S3Error {
        S3Error::new(0, "LocalIoError", e.to_string())
    }
    pub fn cancelled() -> S3Error {
        S3Error::new(0, "Cancelled", "operation cancelled")
    }
    pub fn is_cancelled(&self) -> bool {
        self.code == "Cancelled"
    }

    /// Short human explanation of the error code.
    pub fn friendly(&self) -> String {
        let s = match self.code.as_str() {
            "InvalidAccessKeyId" => "The Access Key ID is not valid",
            "SignatureDoesNotMatch" => "The Secret Access Key is wrong (signature mismatch)",
            "NoSuchBucket" => "The bucket does not exist",
            "AccessDenied" | "Forbidden" => "Access denied: these credentials may not do this on the bucket",
            "AllAccessDisabled" => "All access to this bucket has been disabled",
            "NoSuchKey" | "NotFound" => "The object does not exist",
            "RequestTimeTooSkewed" => "This computer's clock is too far off from the server's",
            "ExpiredToken" | "InvalidToken" => "The session token is invalid or expired",
            "PermanentRedirect" | "AuthorizationHeaderMalformed" | "IllegalLocationConstraintException" => {
                "The bucket is in a different region"
            }
            "BucketAlreadyOwnedByYou" => "You already own this bucket",
            "BucketAlreadyExists" => "That bucket name is taken",
            "EntityTooLarge" => "The object is too large",
            "SlowDown" | "TooManyRequests" => "The server is throttling requests",
            "InternalError" | "ServiceUnavailable" => "The storage service had an internal error",
            "NetworkError" => "Network error (could not reach the storage server)",
            "LocalIoError" => "Could not read or write a local file",
            "Cancelled" => "Cancelled",
            _ => "",
        };
        s.to_string()
    }
}

impl fmt::Display for S3Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let fr = self.friendly();
        let detail = if self.status == 0 { self.code.clone() } else { format!("{}, HTTP {}", self.code, self.status) };
        match (fr.is_empty(), self.message.is_empty()) {
            (true, true) => write!(f, "S3 error [{}]", detail),
            (true, false) => write!(f, "{} [{}]", self.message, detail),
            (false, true) => write!(f, "{} [{}]", fr, detail),
            (false, false) => write!(f, "{}: {} [{}]", fr, self.message, detail),
        }
    }
}

impl std::error::Error for S3Error {}
