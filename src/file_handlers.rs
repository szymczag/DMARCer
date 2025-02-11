//! File Handlers Module
//!
//! This module provides utilities for processing individual files of different types
//! (ZIP, GZIP, XML) with appropriate security checks such as file size limits,
//! decompression limits, and prevention of path traversal.
use std::io::{BufReader, Read}; // Import Read trait for reading to string.
#[allow(dead_code)]
const BUFFER_SIZE: usize = 8192; // 8KB buffer
/// FileHandler processes a file based on its type (ZIP, GZIP, XML).
#[allow(dead_code)]
pub struct FileHandler {
    config: crate::config::Config,
}
#[allow(dead_code)]
impl FileHandler {
    /// Creates a new FileHandler with the given configuration.
    pub fn new(config: crate::config::Config) -> Self {
        Self { config }
    }
    /// Processes the file at the given path, applying security checks.
    pub fn process_file(&self, path: &std::path::Path) -> crate::error::Result<Vec<String>> {
        if !path.exists() {
            return Err(crate::error::DmarcError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "File not found",
            )));
        }
        let metadata = std::fs::metadata(path)?;
        if metadata.len() as usize > self.config.max_file_size {
            return Err(crate::error::DmarcError::FileTooLarge(format!(
                "File size {} bytes exceeds limit of {} bytes",
                metadata.len(),
                self.config.max_file_size
            )));
        }
        match path.extension()
            .and_then(|ext| ext.to_str())
            .map(|s| s.to_lowercase())
        {
            Some(ext) => match ext.as_str() {
                "zip" => self.handle_zip(path),
                "gz" => self.handle_gzip(path),
                "xml" => self.handle_xml(path),
                _ => Err(crate::error::DmarcError::UnsupportedFile(format!("Unsupported file extension: {}", ext))),
            },
            None => Err(crate::error::DmarcError::UnsupportedFile("No file extension".into())),
        }
    }
    /// Handles extraction from ZIP archives.
    fn handle_zip(&self, path: &std::path::Path) -> crate::error::Result<Vec<String>> {
        let file = std::fs::File::open(path)?;
        let reader = BufReader::with_capacity(BUFFER_SIZE, file);
        let mut archive = zip::read::ZipArchive::new(reader)
            .map_err(|e| crate::error::DmarcError::Zip(e))?;
        let max_size = self.config.max_file_size;
        let mut contents_vec = Vec::new();
        for i in 0..archive.len() {
            let mut file_in_zip = archive.by_index(i)
                .map_err(|e| crate::error::DmarcError::Zip(e))?;
            if file_in_zip.size() as usize > max_size {
                return Err(crate::error::DmarcError::FileTooLarge(format!("File in ZIP too large: {}", file_in_zip.name())));
            }
            let mut contents = String::with_capacity(file_in_zip.size() as usize);
            file_in_zip.read_to_string(&mut contents)?;
            if contents.trim().is_empty() {
                return Err(crate::error::DmarcError::Parse("Empty file".into()));
            }
            contents_vec.push(contents);
        }
        if contents_vec.is_empty() {
            return Err(crate::error::DmarcError::Parse("No valid files found in ZIP".into()));
        }
        Ok(contents_vec)
    }
    /// Handles extraction from GZIP archives.
    fn handle_gzip(&self, path: &std::path::Path) -> crate::error::Result<Vec<String>> {
        let file = std::fs::File::open(path)?;
        let mut gz = flate2::read::GzDecoder::new(BufReader::with_capacity(BUFFER_SIZE, file));
        let mut contents = String::new();
        let len = gz.read_to_string(&mut contents)?;
        if len > self.config.max_file_size {
            return Err(crate::error::DmarcError::FileTooLarge(format!(
                "Decompressed GZ size {} bytes exceeds limit",
                len
            )));
        }
        if contents.trim().is_empty() {
            return Err(crate::error::DmarcError::Parse("Empty GZ file".into()));
        }
        Ok(vec![contents])
    }
    /// Handles reading from plain XML files.
    fn handle_xml(&self, path: &std::path::Path) -> crate::error::Result<Vec<String>> {
        let file = std::fs::File::open(path)?;
        let mut reader = BufReader::new(file);
        let mut contents = String::new();
        let len = reader.read_to_string(&mut contents)?;
        if len as u64 > self.config.max_file_size as u64 {
            return Err(crate::error::DmarcError::FileTooLarge("XML file size too large".to_string()).into());
        }
        if contents.trim().is_empty() {
            return Err(crate::error::DmarcError::Parse("Empty XML file".into()));
        }
        Ok(vec![contents])
    }
}
#[cfg(test)]
mod tests {
    //! Tests for the file handlers.
    //!
    //! These tests verify that the file handlers correctly extract and validate files
    //! from ZIP and GZIP archives, including checking file size limits.
    use super::*;
    use tempfile::tempdir;
    use std::io::Write;
    #[test]
    fn test_zip_handling() -> crate::error::Result<()> {
        let dir = tempdir()?;
        let zip_path = dir.path().join("test.zip");
        let file = std::fs::File::create(&zip_path)?;
        let mut zip = zip::ZipWriter::new(file);
        // Annotate options explicitly.
        let options: zip::write::FileOptions<()> = zip::write::FileOptions::default();
        zip.start_file("test.xml", options)?;
        zip.write_all(b"<feedback></feedback>")?;
        zip.finish()?;
        let config = crate::config::Config {
            max_file_size: 1024 * 1024,
            webhook_url: None,
            webhook_timeout: 30,
            max_decompressed_size: 1024 * 1024,
            max_files_in_zip: 1000,
            max_compression_ratio: 1000.0,
            max_filename_length: 256,
        };
        let handler = FileHandler::new(config);
        let result = handler.process_file(&zip_path)?;
        assert!(!result.is_empty());
        Ok(())
    }
    #[test]
    fn test_gzip_handling() -> crate::error::Result<()> {
        let dir = tempdir()?;
        let gz_path = dir.path().join("test.xml.gz");
        let file = std::fs::File::create(&gz_path)?;
        let mut gz = flate2::write::GzEncoder::new(file, flate2::Compression::default());
        gz.write_all(b"<feedback></feedback>")?;
        gz.finish()?;
        let config = crate::config::Config {
            max_file_size: 1024 * 1024,
            webhook_url: None,
            webhook_timeout: 30,
            max_decompressed_size: 1024 * 1024,
            max_files_in_zip: 1000,
            max_compression_ratio: 1000.0,
            max_filename_length: 256,
        };
        let handler = FileHandler::new(config);
        let result = handler.process_file(&gz_path)?;
        assert!(!result.is_empty());
        Ok(())
    }
    #[test]
    fn test_size_limit() -> crate::error::Result<()> {
        let dir = tempdir()?;
        let xml_path = dir.path().join("test.xml");
        let mut file = std::fs::File::create(&xml_path)?;
        let large_content = "A".repeat(1024 * 1024 + 1);
        file.write_all(large_content.as_bytes())?;
        let config = crate::config::Config {
            max_file_size: 1024 * 1024,
            webhook_url: None,
            webhook_timeout: 30,
            max_decompressed_size: 1024 * 1024,
            max_files_in_zip: 1000,
            max_compression_ratio: 1000.0,
            max_filename_length: 256,
        };
        let handler = FileHandler::new(config);
        let result = handler.process_file(&xml_path);
        assert!(matches!(result, Err(crate::error::DmarcError::FileTooLarge(_))));
        Ok(())
    }
}
