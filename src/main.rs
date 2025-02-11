//! DMARCer - Next-gen DMARC Report Analyzer
//!
//! This tool extracts, parses, and analyzes DMARC reports from ZIP archives.
//! It displays the published DMARC policy and details about each record’s SPF and DKIM results.
//!
//! The tool outputs results in one of three formats: Table, CSV, or JSON.
//! The CLI help message has been improved for clarity.

mod config;
mod error;
mod models;
mod zip_handler;
mod xml_parser;
mod geo;
mod webhook;
mod file_handlers;

use clap::Parser;
use colored::*;
use config::Config;
use zip_handler::extract_zip;
use crate::xml_parser::parse_dmarc_xml;
use anyhow::{Result, Context};
use serde::{Deserialize, Serialize};
use prettytable::{Table, Row, Cell, row};
use std::path::PathBuf;
use std::str::FromStr;
use models::DmarcRecord;

/// CLI arguments for DMARCer.
#[derive(Parser, Debug)]
#[command(
    author,
    version,
    about = "Next-gen DMARC report analyzer in Rust",
    long_about = "DMARCer extracts, parses, and analyzes DMARC reports from ZIP archives. \
                  It displays the published DMARC policy and detailed SPF/DKIM results.\n\n\
                  USAGE:\n  dmarcer <FILE> [--output <table|csv|json>] [--verbose]",
    usage = "dmarcer <FILE> [OPTIONS]"
)]
struct Cli {
    /// Path to DMARC ZIP report
    #[arg(value_parser)]
    file: PathBuf,

    /// Output format: table, csv, json
    #[arg(short, long, default_value = "table")]
    output: OutputFormat,

    /// Enable verbose logging
    #[arg(short, long)]
    verbose: bool,
}

/// Supported output formats.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum OutputFormat {
    Table,
    Csv,
    Json,
}

impl FromStr for OutputFormat {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "table" => Ok(OutputFormat::Table),
            "csv" => Ok(OutputFormat::Csv),
            "json" => Ok(OutputFormat::Json),
            _ => Err(format!("Invalid output format: {}", s)),
        }
    }
}

/// Formats a DKIM result into a clear, human-readable string.
/// If no signature is present, returns "No signature".
fn format_dkim(d: &models::DkimResult) -> String {
    if d.domain.trim().is_empty() {
        "No signature".to_string()
    } else if d.selector.trim().is_empty() {
        format!("{}:{}", d.domain, d.result)
    } else {
        format!("{} (selector: {}): {}", d.domain, d.selector, d.result)
    }
}

/// Formats an SPF result into a clear, human-readable string.
/// If no SPF record is present, returns "No SPF record".
fn format_spf(spf: &models::SpfResult) -> String {
    if spf.domain.trim().is_empty() {
        "No SPF record".to_string()
    } else {
        format!("{}:{}", spf.domain, spf.result)
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    
    // Initialize logging based on verbosity.
    env_logger::Builder::from_env(env_logger::Env::default())
        .filter_level(if cli.verbose { log::LevelFilter::Debug } else { log::LevelFilter::Info })
        .init();

    println!(
        "{}\n{}\n",
        "DMARCer - Next-gen DMARC Report Analyzer".bold().green(),
        "Extracting, parsing & analyzing DMARC data".dimmed()
    );

    log::info!("Processing file: {}", cli.file.display());
    let config = Config::new().context("Failed to load configuration")?;

    let extracted_files = extract_zip(&cli.file, &config)
        .context("Failed to extract file")?;

    let mut results = Vec::new();
    let mut policy_info = None;

    for xml in &extracted_files {
        let (records, policy) = parse_dmarc_xml(xml)
            .context("Failed to parse DMARC XML")?;
        results.extend(records);
        policy_info = Some(policy);
    }

    match cli.output {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&results)?);
        }
        OutputFormat::Csv => {
            let mut wtr = csv::Writer::from_writer(std::io::stdout());
            for record in &results {
                wtr.serialize(record)?;
            }
            wtr.flush()?;
        }
        OutputFormat::Table => {
            if let Some(policy) = policy_info.as_ref() {
                println!("{}", "DMARC Policy Information".bold().blue());
                println!("{}", "----------------------------".dimmed());
                println!("{}: {}", "Domain".bold(), policy.domain);
                println!("{}: {}", "SPF Alignment".bold(), policy.aspf);
                println!("{}: {}", "DKIM Alignment".bold(), policy.adkim);
                println!("{}: {}", "Policy".bold(), policy.policy);
                println!("{}: {}\n", "Percentage Applied".bold(), policy.pct);
            }

            if !results.is_empty() {
                let mut table = Table::new();
                table.add_row(row!["Source IP", "Count", "SPF", "DKIM"]);
                
                for record in &results {
                    let spf_str = format_spf(&record.spf);
                    let dkim_results: Vec<String> = record.dkim.iter()
                        .map(|d| format_dkim(d))
                        .collect();
                    // Bind the joined string to a variable for a longer lifetime.
                    let dkim_str = if dkim_results.is_empty() {
                        "No DKIM signature".to_string()
                    } else {
                        dkim_results.join(", ")
                    };
                    
                    table.add_row(Row::new(vec![
                        Cell::new(&record.source_ip),
                        Cell::new(&record.count.to_string()),
                        Cell::new(&spf_str),
                        Cell::new(&dkim_str),
                    ]));
                }
                
                table.printstd();
            } else {
                println!("{}", "No DMARC records found.".yellow());
            }
        }
    }

    if let Some(url) = &config.webhook_url {
        log::info!("Sending results to webhook: {}", url);
        send_webhook(url, &results).await?;
    }

    log::info!("{}", "Analysis complete!".bold().cyan());
    Ok(())
}

/// Sends webhook data if a webhook URL is configured.
async fn send_webhook(url: &str, results: &[DmarcRecord]) -> Result<()> {
    let client = reqwest::Client::new();
    client
        .post(url)
        .json(results)
        .send()
        .await
        .context("Failed to send webhook")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_output_format_parsing() {
        assert!(matches!(OutputFormat::from_str("table"), Ok(OutputFormat::Table)));
        assert!(matches!(OutputFormat::from_str("csv"), Ok(OutputFormat::Csv)));
        assert!(matches!(OutputFormat::from_str("json"), Ok(OutputFormat::Json)));
        assert!(OutputFormat::from_str("invalid").is_err());
    }
}
