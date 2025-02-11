//! Error Handling Module
//!
//! This module defines custom error types for DMARCer using the `thiserror` crate.

use thiserror::Error;

#[derive(Error, Debug)]
pub enum DmarcError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("ZIP error: {0}")]
    Zip(#[from] zip::result::ZipError),

    #[error("XML error: {0}")]
    Xml(#[from] quick_xml::Error),

    #[error("Invalid format: {0}")]
    Format(String),

    #[error("File too large: {0}")]
    FileTooLarge(String),

    #[error("Unsupported file type: {0}")]
    UnsupportedFile(String),

    #[allow(dead_code)]
    #[error("Geolocation error: {0}")]
    Geolocation(String),

    #[allow(dead_code)]
    #[error("Parse error: {0}")]
    Parse(String),
}

pub type Result<T> = std::result::Result<T, DmarcError>;
