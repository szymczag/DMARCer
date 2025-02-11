//! Configuration Module
//!
//! This module reads configuration values from environment variables, provides
//! sensible defaults, and validates key security parameters such as maximum file
//! sizes and decompression limits.

use anyhow::Result;
use std::env;

#[derive(Debug)]
pub struct Config {
    pub webhook_url: Option<String>,
    #[allow(dead_code)]
    pub webhook_timeout: u64,
    pub max_file_size: usize,
    pub max_decompressed_size: usize,
    pub max_files_in_zip: usize,
    pub max_compression_ratio: f64,
    pub max_filename_length: usize,
}

impl Config {
    /// Creates a new configuration by reading environment variables.
    /// If a variable is missing or empty, a default value is used.
    pub fn new() -> Result<Self> {
        // Read max file size from env or use default 10MB.
        let max_file_size = env::var("DMARC_MAX_FILE_SIZE")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(10 * 1024 * 1024);

        if max_file_size > 500_000_000 {
            return Err(anyhow::anyhow!("Max file size too large (500MB limit)"));
        }

        // For webhook_timeout, try DMARC_WEBHOOK_TIMEOUT_SECS then DMARC_WEBHOOK_TIMEOUT.
        let webhook_timeout = env::var("DMARC_WEBHOOK_TIMEOUT_SECS")
            .or_else(|_| env::var("DMARC_WEBHOOK_TIMEOUT"))
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(30);

        let max_decompressed_size = env::var("DMARC_MAX_DECOMPRESSED_SIZE")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(100 * 1024 * 1024);

        let max_files_in_zip = env::var("DMARC_MAX_FILES_IN_ZIP")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(1000);

        let max_compression_ratio = env::var("DMARC_MAX_COMPRESSION_RATIO")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(1000.0);

        let max_filename_length = env::var("DMARC_MAX_FILENAME_LENGTH")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(256);

        // Trim the webhook URL before checking for emptiness.
        let webhook_url = env::var("DMARC_WEBHOOK_URL")
            .map(|s| s.trim().to_string())
            .ok()
            .filter(|s| !s.is_empty());

        Ok(Config {
            webhook_url,
            webhook_timeout,
            max_file_size,
            max_decompressed_size,
            max_files_in_zip,
            max_compression_ratio,
            max_filename_length,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    #[test]
    fn test_config_defaults() {
        // Remove environment variables so that defaults are used.
        env::remove_var("DMARC_WEBHOOK_URL");
        env::remove_var("DMARC_MAX_FILE_SIZE");
        env::remove_var("DMARC_WEBHOOK_TIMEOUT_SECS");
        env::remove_var("DMARC_MAX_DECOMPRESSED_SIZE");
        env::remove_var("DMARC_MAX_FILES_IN_ZIP");
        env::remove_var("DMARC_MAX_COMPRESSION_RATIO");
        env::remove_var("DMARC_MAX_FILENAME_LENGTH");

        let config = Config::new().unwrap();
        // webhook_url should be None when not set.
        assert!(config.webhook_url.is_none());
        assert_eq!(config.max_file_size, 10 * 1024 * 1024);
        assert_eq!(config.webhook_timeout, 30);
        assert_eq!(config.max_decompressed_size, 100 * 1024 * 1024);
        assert_eq!(config.max_files_in_zip, 1000);
        assert_eq!(config.max_compression_ratio, 1000.0);
        assert_eq!(config.max_filename_length, 256);
    }

    #[test]
    fn test_config_from_env() {
        // Set environment variables for testing.
        env::set_var("DMARC_WEBHOOK_URL", "http://example.com");
        env::set_var("DMARC_MAX_FILE_SIZE", "5242880"); // 5MB
        env::set_var("DMARC_WEBHOOK_TIMEOUT_SECS", "60");
        env::set_var("DMARC_MAX_DECOMPRESSED_SIZE", "10485760"); // 10MB
        env::set_var("DMARC_MAX_FILES_IN_ZIP", "500");
        env::set_var("DMARC_MAX_COMPRESSION_RATIO", "500.0");
        env::set_var("DMARC_MAX_FILENAME_LENGTH", "128");

        let config = Config::new().unwrap();
        assert_eq!(config.webhook_url, Some("http://example.com".to_string()));
        assert_eq!(config.max_file_size, 5242880);
        assert_eq!(config.webhook_timeout, 60);
        assert_eq!(config.max_decompressed_size, 10485760);
        assert_eq!(config.max_files_in_zip, 500);
        assert_eq!(config.max_compression_ratio, 500.0);
        assert_eq!(config.max_filename_length, 128);
    }
}
