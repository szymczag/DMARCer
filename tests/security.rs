/// Security tests for DMARCer.
///
/// This module verifies that the analyzer is protected against common attacks:
/// - ZIP Bombs (by enforcing decompression and file count limits)
/// - XML External Entity (XXE) Injection
/// - Directory Traversal attacks in archive filenames
/// - Billion Laughs (recursive XML entity) attacks
use std::fs::File;
use std::io::Write;
use tempfile::tempdir;
use std::time::Instant;
use anyhow::Result;
use zip::write::FileOptions;
#[cfg(test)]
mod tests {
    use super::*;
    use dmarcer::{extract_zip, parse_dmarc_xml, Config};
    const MAX_PROCESSING_TIME_MS: u128 = 2000; // 2 seconds for test
    const TEST_BOMB_SIZE: usize = 2 * 1024 * 1024; // 2MB bomb for test
    /// Test protection against a ZIP bomb attack.
    #[test]
    fn test_zip_bomb_protection() -> Result<()> {
        let dir = tempdir()?;
        let zip_path = dir.path().join("zipbomb.zip");
        let file = File::create(&zip_path)?;
        let mut zip = zip::ZipWriter::new(file);
        let options = FileOptions::default().compression_method(zip::CompressionMethod::Deflated);
        zip.start_file("large.xml", options)?;
        // Create a test bomb of 2MB
        let large_chunk = "A".repeat(TEST_BOMB_SIZE);
        zip.write_all(large_chunk.as_bytes())?;
        zip.finish()?;
        // Override configuration to set max_decompressed_size to 1MB for testing
        let mut config = Config::new()?;
        config.max_decompressed_size = 1 * 1024 * 1024; // 1MB
        let start = Instant::now();
        let result = extract_zip(&zip_path, &config);
        let duration = start.elapsed();
        debug_assert!(
            duration.as_millis() < MAX_PROCESSING_TIME_MS,
            "ZIP bomb processing too slow: {:?}",
            duration
        );
        match result {
            Ok(files) => assert!(files.is_empty(), "ZIP bomb should be blocked"),
            Err(e) => assert!(
                e.to_string().contains("too large") || e.to_string().contains("Suspicious compression ratio"),
                "Unexpected error: {}",
                e
            ),
        }
        Ok(())
    }
    /// Test protection against XXE (XML External Entity Injection).
    #[test]
    fn test_xxe_protection() {
        let xml = r#"
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE foo [
            <!ENTITY xxe SYSTEM "file:///etc/passwd">
        ]>
        <feedback>
            <record>
                <source_ip>1.2.3.4</source_ip>
                <count>1</count>
                <header_from>example.com</header_from>
            </record>
        </feedback>
        "#;
        let result = parse_dmarc_xml(xml);
        assert!(result.is_ok(), "Parser should handle malicious XML safely");
        let (records, _) = result.unwrap();
        for record in records {
            assert!(
                !record.source_ip.contains("/etc/passwd"),
                "XXE allowed system file read"
            );
        }
    }
    /// Test protection against directory traversal in ZIP file entries.
    #[test]
    fn test_directory_traversal_protection() -> Result<()> {
        let dir = tempdir()?;
        let zip_path = dir.path().join("traversal.zip");
        let file = File::create(&zip_path)?;
        let mut zip = zip::ZipWriter::new(file);
        let options = FileOptions::default();
        zip.start_file("../../../etc/passwd", options)?;
        zip.write_all(b"fake passwd file")?;
        zip.finish()?;
        let config = Config::new()?;
        let result = extract_zip(&zip_path, &config);
        assert!(result.is_err(), "Should block directory traversal attempt");
        Ok(())
    }
    /// Test protection against the Billion Laughs attack (recursive XML entities).
    #[test]
    fn test_billion_laughs_protection() {
        let xml = r#"
        <?xml version="1.0"?>
        <!DOCTYPE lolz [
            <!ENTITY lol "lol">
            <!ENTITY lol2 "&lol;&lol;">
            <!ENTITY lol3 "&lol2;&lol2;">
            <!ENTITY lol4 "&lol3;&lol3;">
            <!ENTITY lol5 "&lol4;&lol4;">
            <!ENTITY lol6 "&lol5;&lol5;">
            <!ENTITY lol7 "&lol6;&lol6;">
            <!ENTITY lol8 "&lol7;&lol7;">
            <!ENTITY lol9 "&lol8;&lol8;">
        ]>
        <feedback>
            <record>
                <source_ip>1.2.3.4</source_ip>
                <count>1</count>
                <header_from>example.com</header_from>
            </record>
        </feedback>
        "#;
        let start = Instant::now();
        let result = parse_dmarc_xml(xml);
        let duration = start.elapsed();
        assert!(
            duration.as_millis() < MAX_PROCESSING_TIME_MS,
            "XML Billion Laughs was not blocked in time"
        );
        assert!(result.is_err(), "Parser should reject recursive entities");
    }
}
