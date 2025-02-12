//! XML Parser Module
//!
//! DMARCer parses DMARC XML reports and extracts DMARC records and published policy information.
//! It enforces a recursion depth limit to protect against attacks (such as the Billion Laughs attack).
//! Additionally, it completely removes any DOCTYPE declaration from the XML.
//! If the DOCTYPE block defines two or more entity definitions, the XML is rejected.
//! This ensures that DMARC reports (which do not require DTD processing) are parsed safely.

use crate::error::{DmarcError, Result};
use crate::models::{DmarcRecord, DmarcPolicy, DkimResult, SpfResult, DateRange};
use crate::models::{DkimVerdict, SpfVerdict, AlignmentMode, PolicyType};
use quick_xml::events::Event;
use quick_xml::Reader;
use regex::Regex;
use std::io;

pub fn parse_dmarc_xml(xml_content: &str) -> Result<(Vec<DmarcRecord>, DmarcPolicy)> {
    // Use a regex to locate the DOCTYPE block.
    let re = Regex::new(r"(?s)<!DOCTYPE.*?\]>").unwrap();
    let cleaned_xml = if let Some(mat) = re.find(xml_content) {
        let doctype_block = mat.as_str();
        // Count the number of entity definitions within the DOCTYPE block.
        let entity_count = doctype_block.matches("<!ENTITY").count();
        if entity_count >= 2 {
            return Err(DmarcError::Xml(quick_xml::Error::from(
                io::Error::new(io::ErrorKind::Other, "Recursive entities detected")
            )));
        }
        // Remove the DOCTYPE block entirely.
        re.replace_all(xml_content, "").to_string()
    } else {
        xml_content.to_string()
    };

    let mut reader = Reader::from_str(&cleaned_xml);
    // quick_xml v0.37.2 does not offer a trim_text method, so we trim each text value individually.
    let mut records = Vec::new();
    let mut policy = DmarcPolicy {
        domain: String::new(),
        adkim: AlignmentMode::Relaxed,
        aspf: AlignmentMode::Relaxed,
        policy: PolicyType::None,
        pct: 100,
    };

    let mut current_record: Option<DmarcRecord> = None;
    let mut in_auth_results = false;
    let mut depth: u32 = 0;
    let max_depth = 100; // Increased depth limit to allow valid DMARC reports

    loop {
        match reader.read_event() {
            Ok(Event::Start(ref e)) => {
                depth += 1;
                if depth > max_depth {
                    return Err(DmarcError::Xml(quick_xml::Error::from(
                        io::Error::new(io::ErrorKind::Other, "XML recursion depth limit exceeded")
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
                    b"auth_results" => {
                        in_auth_results = true;
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
                        if in_auth_results {
                            if let Some(record) = current_record.as_mut() {
                                let dkim = parse_dkim(&mut reader)?;
                                record.dkim.push(dkim);
                            }
                        }
                    }
                    b"spf" => {
                        if in_auth_results {
                            if let Some(record) = current_record.as_mut() {
                                record.spf = parse_spf(&mut reader)?;
                            }
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
                    b"auth_results" => {
                        in_auth_results = false;
                    }
                    _ => {}
                }
                depth = depth.saturating_sub(1);
            }
            Ok(Event::Eof) => break,
            Err(e) => return Err(DmarcError::Xml(e)),
            _ => {}
        }
    }

    Ok((records, policy))
}

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
            _ => {}
        }
    }
    Ok(DkimResult {
        domain,
        selector,
        result: result_dkim,
    })
}

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
            _ => {}
        }
    }
    Ok(SpfResult {
        domain,
        scope,
        result: result_spf,
    })
}
