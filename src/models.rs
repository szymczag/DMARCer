//! Data Models Module
//!
//! This module defines the core data structures used by DMARCer to represent
//! DMARC reports, policies, and associated results (DKIM, SPF, etc.). It also
//! provides implementations for converting from strings and default values.
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Default)]
pub struct DmarcPolicy {
    pub domain: String,
    pub adkim: AlignmentMode,
    pub aspf: AlignmentMode,
    pub policy: PolicyType,
    pub pct: u8,
}
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DmarcRecord {
    pub source_ip: String,
    pub count: u32,
    pub policy_evaluated: PolicyEvaluated,
    pub header_from: String,
    pub envelope_from: Option<String>,
    pub dkim: Vec<DkimResult>,
    pub spf: SpfResult,
    pub date_range: DateRange,
}
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct PolicyEvaluated {
    pub disposition: String,
    pub dkim: DkimVerdict,
    pub spf: SpfVerdict,
}
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DkimResult {
    pub domain: String,
    pub selector: String,
    pub result: DkimVerdict,
}
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct SpfResult {
    pub domain: String,
    pub scope: String,
    pub result: SpfVerdict,
}
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DateRange {
    pub begin: i64,
    pub end: i64,
}
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Default)]
pub enum DkimVerdict {
    #[default]
    None,
    Pass,
    Fail,
    Neutral,
}
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Default)]
pub enum SpfVerdict {
    #[default]
    None,
    Pass,
    Fail,
    Neutral,
}
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Default)]
pub enum AlignmentMode {
    #[default]
    Relaxed,
    Strict,
}
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Default)]
pub enum PolicyType {
    #[default]
    None,
    Quarantine,
    Reject,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpGeoInfo {
    pub country: String,
    pub city: Option<String>,
    pub latitude: f64,
    pub longitude: f64,
    pub asn: Option<String>,
    pub organization: Option<String>,
}
impl fmt::Display for DkimVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DkimVerdict::None => write!(f, "none"),
            DkimVerdict::Pass => write!(f, "pass"),
            DkimVerdict::Fail => write!(f, "fail"),
            DkimVerdict::Neutral => write!(f, "neutral"),
        }
    }
}
impl fmt::Display for SpfVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SpfVerdict::None => write!(f, "none"),
            SpfVerdict::Pass => write!(f, "pass"),
            SpfVerdict::Fail => write!(f, "fail"),
            SpfVerdict::Neutral => write!(f, "neutral"),
        }
    }
}
impl fmt::Display for AlignmentMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AlignmentMode::Relaxed => write!(f, "relaxed"),
            AlignmentMode::Strict => write!(f, "strict"),
        }
    }
}
impl fmt::Display for PolicyType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PolicyType::None => write!(f, "none"),
            PolicyType::Quarantine => write!(f, "quarantine"),
            PolicyType::Reject => write!(f, "reject"),
        }
    }
}
impl FromStr for DkimVerdict {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "pass" => Ok(DkimVerdict::Pass),
            "fail" => Ok(DkimVerdict::Fail),
            "neutral" => Ok(DkimVerdict::Neutral),
            "none" => Ok(DkimVerdict::None),
            _ => Err(format!("Invalid DKIM verdict: {}", s)),
        }
    }
}
impl FromStr for SpfVerdict {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "pass" => Ok(SpfVerdict::Pass),
            "fail" => Ok(SpfVerdict::Fail),
            "neutral" => Ok(SpfVerdict::Neutral),
            "none" => Ok(SpfVerdict::None),
            _ => Err(format!("Invalid SPF verdict: {}", s)),
        }
    }
}
impl FromStr for AlignmentMode {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "r" | "relaxed" => Ok(AlignmentMode::Relaxed),
            "s" | "strict" => Ok(AlignmentMode::Strict),
            _ => Err(format!("Invalid alignment mode: {}", s)),
        }
    }
}
impl FromStr for PolicyType {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "none" => Ok(PolicyType::None),
            "quarantine" => Ok(PolicyType::Quarantine),
            "reject" => Ok(PolicyType::Reject),
            _ => Err(format!("Invalid policy type: {}", s)),
        }
    }
}
