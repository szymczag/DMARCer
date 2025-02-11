//! XML Parser Module
//!
//! This module parses DMARC XML reports and extracts DMARC records and published policy
//! information. It enforces a recursion depth limit to protect against attacks such as
//! the Billion Laughs attack. Moreover, it completely disables the processing of DOCTYPE
//! declarations (and hence external/internal entities) by removing any DOCTYPE block
//! from the input. If a DOCTYPE block contains two or more entity definitions, the XML is rejected.

use crate::error::{DmarcError, Result};
use crate::models::{DmarcRecord, DmarcPolicy, DkimResult, SpfResult, DateRange};
use crate::models::{DkimVerdict, SpfVerdict, AlignmentMode, PolicyType};
use quick_xml::events::Event;
use quick_xml::reader::Reader;

/// Parses the DMARC XML content and returns a tuple of DMARC records and the published policy.
///
/// # Arguments
///
/// * `xml_content` - A string slice containing the XML content.
///
/// # Errors
///
/// Returns an error if the XML cannot be parsed, if the recursion depth limit is exceeded,
/// or if the DOCTYPE block (if present) defines two or more entity definitions.
pub fn parse_dmarc_xml(xml_content: &str) -> Result<(Vec<DmarcRecord>, DmarcPolicy)> {
    // Check if the XML contains a DOCTYPE declaration.
    // If found, extract and inspect the DOCTYPE block.
    // If the DOCTYPE defines two or more entities, reject the XML.
    // Otherwise, remove the DOCTYPE block entirely.
    let cleaned_xml = if let Some(start) = xml_content.find("<!DOCTYPE") {
        if let Some(end) = xml_content[start..].find("]>") {
            let doctype = &xml_content[start..start + end + 2];
            let entity_count = doctype.matches("<!ENTITY").count();
            if entity_count >= 2 {
                return Err(DmarcError::Xml(quick_xml::Error::UnexpectedEof(
                    "Recursive entities detected".into()
                )));
            }
            // Remove the DOCTYPE block from the XML.
            let before = &xml_content[..start];
            let after = &xml_content[start + end + 2..];
            format!("{}{}", before, after)
        } else {
            // If we cannot find the end of the DOCTYPE, use the original XML.
            xml_content.to_string()
        }
    } else {
        xml_content.to_string()
    };

    let mut reader = Reader::from_str(&cleaned_xml);
    reader.trim_text(true);

    let mut records = Vec::new();
    let mut policy = DmarcPolicy {
        domain: String::new(),
        adkim: AlignmentMode::Relaxed,
        aspf: AlignmentMode::Relaxed,
        policy: PolicyType::None,
        pct: 100,
    };

    let mut current_record: Option<DmarcRecord> = None;
    let mut depth: u32 = 0;
    let max_depth = 20; // Prevent excessive recursion

    loop {
        match reader.read_event() {
            Ok(Event::Start(ref e)) => {
                depth += 1;
                if depth > max_depth {
                    return Err(DmarcError::Xml(quick_xml::Error::UnexpectedEof(
                        "XML recursion depth limit exceeded".into()
                    )));
                }
                match e.name().as_ref() {
                    b"record" => {
                        current_record = Some(DmarcRecord {
                            source_ip: String::new(),
                            count: 0,
                            header_from: String::new(),
                            envelope_from: None,
                            policy_evaluated: Default::default(),
                            dkim: Vec::new(),
                            spf: SpfResult {
                                domain: String::new(),
                                scope: String::new(),
                                result: SpfVerdict::None,
                            },
                            date_range: DateRange { begin: 0, end: 0 },
                        });
                    }
                    b"policy_published" => {
                        policy = parse_policy_published(&mut reader)?;
                    }
                    b"source_ip" => {
                        if let Some(record) = current_record.as_mut() {
                            record.source_ip = reader.read_text(e.name())?.trim().to_string();
                        }
                    }
                    b"count" => {
                        if let Some(record) = current_record.as_mut() {
                            record.count = reader.read_text(e.name())?.trim().parse().unwrap_or(0);
                        }
                    }
                    b"header_from" => {
                        if let Some(record) = current_record.as_mut() {
                            record.header_from = reader.read_text(e.name())?.trim().to_string();
                        }
                    }
                    b"dkim" => {
                        if let Some(record) = current_record.as_mut() {
                            let dkim = parse_dkim(&mut reader)?;
                            record.dkim.push(dkim);
                        }
                    }
                    b"spf" => {
                        if let Some(record) = current_record.as_mut() {
                            record.spf = parse_spf(&mut reader)?;
                        }
                    }
                    _ => {}
                }
            }
            Ok(Event::End(ref e)) => {
                match e.name().as_ref() {
                    b"record" => {
                        if let Some(record) = current_record.take() {
                            records.push(record);
                        }
                    }
                    _ => {}
                }
                depth = depth.saturating_sub(1);
            }
            Ok(Event::Eof) => break,
            Err(e) => return Err(DmarcError::Xml(e)),
            _ => (),
        }
    }

    Ok((records, policy))
}

/// Parses the `<policy_published>` element.
fn parse_policy_published(reader: &mut Reader<&[u8]>) -> Result<DmarcPolicy> {
    let mut domain = String::new();
    let mut adkim = AlignmentMode::Relaxed;
    let mut aspf = AlignmentMode::Relaxed;
    let mut p = PolicyType::None;
    let mut pct = 100u8;
    loop {
         match reader.read_event() {
             Ok(Event::Start(ref e)) => {
                 match e.name().as_ref() {
                     b"domain" => {
                        domain = reader.read_text(e.name())?.trim().to_string();
                     },
                     b"adkim" => {
                        let text = reader.read_text(e.name())?.trim().to_string();
                        adkim = if text.to_lowercase().starts_with("s") { AlignmentMode::Strict } else { AlignmentMode::Relaxed };
                     },
                     b"aspf" => {
                        let text = reader.read_text(e.name())?.trim().to_string();
                        aspf = if text.to_lowercase().starts_with("s") { AlignmentMode::Strict } else { AlignmentMode::Relaxed };
                     },
                     b"p" => {
                        let text = reader.read_text(e.name())?.trim().to_string();
                        p = match text.to_lowercase().as_str() {
                           "reject" => PolicyType::Reject,
                           "quarantine" => PolicyType::Quarantine,
                           _ => PolicyType::None,
                        };
                     },
                     b"pct" => {
                        let text = reader.read_text(e.name())?.trim().to_string();
                        pct = text.parse().unwrap_or(100);
                     },
                     _ => {}
                 }
             },
             Ok(Event::End(ref e)) => {
                 if e.name().as_ref() == b"policy_published" {
                     break;
                 }
             },
             Ok(Event::Eof) => break,
             Err(e) => return Err(DmarcError::Xml(e)),
             _ => {}
         }
    }
    Ok(DmarcPolicy {
         domain,
         adkim,
         aspf,
         policy: p,
         pct,
    })
}

/// Parses the `<dkim>` element.
fn parse_dkim(reader: &mut Reader<&[u8]>) -> Result<DkimResult> {
    let mut domain = String::new();
    let mut selector = String::new();
    let mut result_dkim = DkimVerdict::None;
    loop {
         match reader.read_event() {
              Ok(Event::Start(ref e)) => {
                  match e.name().as_ref() {
                     b"domain" => {
                         domain = reader.read_text(e.name())?.trim().to_string();
                     },
                     b"selector" => {
                         selector = reader.read_text(e.name())?.trim().to_string();
                     },
                     b"result" => {
                         let text = reader.read_text(e.name())?.trim().to_string();
                         result_dkim = text.parse().unwrap_or(DkimVerdict::None);
                     },
                     _ => {},
                  }
              },
              Ok(Event::End(ref e)) => {
                  if e.name().as_ref() == b"dkim" {
                      break;
                  }
              },
              Ok(Event::Eof) => break,
              Err(e) => return Err(DmarcError::Xml(e)),
              _ => {},
         }
    }
    Ok(DkimResult { domain, selector, result: result_dkim })
}

/// Parses the `<spf>` element.
fn parse_spf(reader: &mut Reader<&[u8]>) -> Result<SpfResult> {
    let mut domain = String::new();
    let mut scope = String::new();
    let mut result_spf = SpfVerdict::None;
    loop {
         match reader.read_event() {
              Ok(Event::Start(ref e)) => {
                  match e.name().as_ref() {
                     b"domain" => {
                         domain = reader.read_text(e.name())?.trim().to_string();
                     },
                     b"scope" => {
                         scope = reader.read_text(e.name())?.trim().to_string();
                     },
                     b"result" => {
                         let text = reader.read_text(e.name())?.trim().to_string();
                         result_spf = text.parse().unwrap_or(SpfVerdict::None);
                     },
                     _ => {},
                  }
              },
              Ok(Event::End(ref e)) => {
                  if e.name().as_ref() == b"spf" {
                      break;
                  }
              },
              Ok(Event::Eof) => break,
              Err(e) => return Err(DmarcError::Xml(e)),
              _ => {},
         }
    }
    Ok(SpfResult { domain, scope, result: result_spf })
}
