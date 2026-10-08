//! The one error type: the message the TypeScript reference throws (or the SDK's own text where it throws one).

use std::fmt;

/// An error carrying the reference's message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error(pub String);

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Error {}

/// `Result<T, Error>`.
pub type Result<T> = std::result::Result<T, Error>;

/// Build an `Error` from anything printable.
pub fn err<T>(msg: impl Into<String>) -> Result<T> {
    Err(Error(msg.into()))
}

impl From<String> for Error {
    fn from(s: String) -> Self {
        Error(s)
    }
}

impl From<&str> for Error {
    fn from(s: &str) -> Self {
        Error(s.to_string())
    }
}
