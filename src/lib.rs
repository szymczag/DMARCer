//! DMARCer Library
//!
//! This library provides the core functionality for DMARCer, including configuration,
//! error handling, data models, file extraction, XML parsing, geolocation, webhook communication,
//! and additional file handling utilities.

pub mod config;
pub mod error;
pub mod models;
pub mod zip_handler;
pub mod xml_parser;
pub mod geo;
pub mod webhook;
pub mod file_handlers;

pub use zip_handler::extract_zip;
pub use xml_parser::parse_dmarc_xml;
pub use config::Config;
