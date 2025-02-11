//! ZIP Handler Module
//!
//! This module handles extraction of DMARC report files from ZIP and GZIP archives.
//! It enforces security measures including file size limits, maximum decompressed
//! size, file count, compression ratio, filename length, and path traversal prevention.
use std::fs::File;
use std::io::{Read, BufReader};
use std::path::Path;
use anyhow::{Result, Context};
use zip::ZipArchive;
use flate2::read::GzDecoder;
use crate::error::DmarcError;
use crate::config::Config;
/// Extracts files from a ZIP, GZIP, or XML file.
///
/// # Arguments
///
/// * `file_path` - The path to the input file.
/// * `config` - Configuration limits for extraction.
///
/// # Security Checks
///
/// - Verifies that the original file size does not exceed the maximum.
/// - For ZIP archives: verifies the number of files, checks for path traversal, file name length,
///   compression ratio, and decompressed size.
/// - For GZIP and XML files: checks the decompressed content size.
pub fn extract_zip<P: AsRef<Path>>(file_path: P, config: &Config) -> Result<Vec<String>> {
    let file = File::open(&file_path).context("Failed to open file")?;
    let file_size = file.metadata()?.len();
    if file_size > config.max_file_size as u64 {
        return Err(DmarcError::FileTooLarge("File too large".to_string()).into());
    }
    let file_name = file_path.as_ref()
        .file_name()
        .map(|x| x.to_string_lossy().to_string())
        .unwrap_or_default();
    let ext = file_name.split('.').last().unwrap_or("").to_lowercase();
    match ext.as_str() {
        "zip" => {
            let mut archive = ZipArchive::new(file)?;
            if archive.len() > config.max_files_in_zip {
                return Err(anyhow::anyhow!("Too many files in archive"));
            }
            let mut extracted = Vec::new();
            for i in 0..archive.len() {
                let mut file_in_zip = archive.by_index(i)?;
                let inner_name = file_in_zip.name().to_string();
                // Prevent path traversal
                if inner_name.contains("..") || inner_name.starts_with('/') || inner_name.starts_with('\\') {
                    return Err(DmarcError::Format(format!("Path traversal attempt detected: {}", inner_name)).into());
                }
                // Check filename length
                if inner_name.len() > config.max_filename_length {
                    return Err(DmarcError::Format("Filename too long".to_string()).into());
                }
                let compressed_size = file_in_zip.compressed_size();
                let uncompressed_size = file_in_zip.size();
                if compressed_size > 0 {
                    let compression_ratio = uncompressed_size as f64 / compressed_size as f64;
                    if compression_ratio > config.max_compression_ratio {
                        return Err(DmarcError::Format(format!("Suspicious compression ratio: {:.2}", compression_ratio)).into());
                    }
                }
                if uncompressed_size > config.max_decompressed_size as u64 {
                    return Err(DmarcError::FileTooLarge("Total decompressed size too large".to_string()).into());
                }
                let mut contents = String::new();
                file_in_zip.read_to_string(&mut contents)?;
                extracted.push(contents);
            }
            Ok(extracted)
        },
        "gz" => {
            let mut gz_decoder = GzDecoder::new(file);
            let mut contents = String::new();
            let len = gz_decoder.read_to_string(&mut contents)?;
            if len > config.max_decompressed_size {
                return Err(DmarcError::FileTooLarge("Decompressed size too large".to_string()).into());
            }
            Ok(vec![contents])
        },
        "xml" => {
            let mut reader = BufReader::new(file);
            let mut contents = String::new();
            let len = reader.read_to_string(&mut contents)?;
            if len as u64 > config.max_file_size as u64 {
                return Err(DmarcError::FileTooLarge("XML file size too large".to_string()).into());
            }
            Ok(vec![contents])
        },
        _ => {
            Err(DmarcError::UnsupportedFile("Unsupported file type".into()).into())
        }
    }
}
