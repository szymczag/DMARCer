//! Unit tests for DMARCer.
//!
//! This module contains basic tests for file extraction and XML parsing.
#![allow(unused)]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::zip_handler::extract_zip;
    use crate::xml_parser::parse_dmarc_xml;
    #[test]
    fn test_zip_extraction() {
        let result = extract_zip("test.zip", &crate::Config::new().unwrap());
        assert!(result.is_ok());
    }
    #[test]
    fn test_xml_parsing() {
        let xml_data = r#"
        <feedback>
            <record>
                <source_ip>1.2.3.4</source_ip>
                <count>1</count>
                <header_from>example.com</header_from>
            </record>
        </feedback>
        "#;
        let result = parse_dmarc_xml(xml_data);
        assert!(result.is_ok());
    }
}
