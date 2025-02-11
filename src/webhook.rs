//! Webhook Module
//!
//! This module provides functionality to send DMARC analysis results
//! to a remote webhook. It supports retries with exponential backoff and
//! properly handles timeouts.
use crate::models::{DmarcRecord, DmarcPolicy};
use anyhow::{Result, Context};
use reqwest::{Client, Url};
use serde::Serialize;
use std::time::Duration;
use tokio::time::sleep;
#[allow(dead_code)]
#[derive(Debug, Serialize)]
struct WebhookPayload {
    records: Vec<DmarcRecord>,
    policy: DmarcPolicy,
    timestamp: chrono::DateTime<chrono::Utc>,
    version: &'static str,
}
/// WebhookHandler is responsible for sending analysis results to a webhook URL.
#[allow(dead_code)]
#[derive(Debug)]
pub struct WebhookHandler {
    #[allow(dead_code)]
    timeout: Duration,
    client: Client,
    url: Url,
    max_retries: u32,
}
#[allow(dead_code)]
impl WebhookHandler {
    /// Creates a new WebhookHandler with the given URL, timeout, and retry count.
    pub fn new(url: impl AsRef<str>, timeout: Duration, max_retries: u32) -> Result<Self> {
        let url = Url::parse(url.as_ref()).context("Invalid webhook URL")?;
        let client = Client::builder()
            .timeout(timeout)
            .build()
            .context("Failed to create HTTP client")?;
        Ok(Self {
            timeout,
            client,
            url,
            max_retries,
        })
    }
    /// Sends the webhook payload asynchronously.
    ///
    /// Retries are attempted with exponential backoff. Returns an error if all retries fail.
    pub async fn send(&self, records: Vec<DmarcRecord>, policy: DmarcPolicy) -> Result<()> {
        let payload = WebhookPayload {
            records,
            policy,
            timestamp: chrono::Utc::now(),
            version: env!("CARGO_PKG_VERSION"),
        };
        let mut last_error = None;
        for retry in 0..=self.max_retries {
            if retry > 0 {
                let delay = Duration::from_secs(2u64.pow(retry - 1));
                log::info!("Retrying webhook send in {:?}...", delay);
                sleep(delay).await;
            }
            match self.client.post(self.url.clone())
                .json(&payload)
                .send()
                .await
            {
                Ok(response) => {
                    if response.status().is_success() {
                        log::info!("Successfully sent webhook (attempt {})", retry + 1);
                        return Ok(());
                    } else {
                        let status = response.status();
                        let body = response.text().await.unwrap_or_else(|_| "Unable to read response body".to_string());
                        log::warn!("Webhook attempt {} failed: HTTP {} - Response: {}", retry + 1, status, body);
                        last_error = Some(format!("HTTP {} - {}", status, body));
                    }
                }
                Err(e) => {
                    log::warn!("Webhook attempt {} encountered error: {}", retry + 1, e);
                    if e.is_timeout() {
                        last_error = Some("timeout".to_string());
                    } else {
                        last_error = Some(e.to_string());
                    }
                }
            }
        }
        Err(anyhow::anyhow!("Webhook failed after {} attempts: {:?}", self.max_retries + 1, last_error))
    }
}
#[cfg(test)]
mod tests {
    //! Tests for the Webhook module.
    //!
    //! These tests verify that the webhook sender:
    //! - Succeeds when the server returns success,
    //! - Retries when the server returns an error,
    //! - Fails after the maximum number of retries, and
    //! - Properly handles timeouts.
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use wiremock::{MockServer, Mock, ResponseTemplate, Respond};
    use wiremock::matchers::*;
    use std::time::Duration;
    /// A helper responder that returns a 500 error on the first request and 200 on subsequent requests.
    struct CounterResponder {
        cc: Arc<AtomicUsize>,
    }
    impl Respond for CounterResponder {
        fn respond(&self, _request: &wiremock::Request) -> ResponseTemplate {
            let count = self.cc.fetch_add(1, Ordering::SeqCst);
            if count == 0 {
                ResponseTemplate::new(500)
            } else {
                ResponseTemplate::new(200)
            }
        }
    }
    #[tokio::test]
    async fn test_webhook_success() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&mock_server)
            .await;
        let handler = WebhookHandler::new(
            mock_server.uri(),
            Duration::from_secs(5),
            3,
        ).unwrap();
        let result = handler.send(vec![], DmarcPolicy::default()).await;
        assert!(result.is_ok());
    }
    #[tokio::test]
    async fn test_webhook_retry() {
        let mock_server = MockServer::start().await;
        let call_count = Arc::new(AtomicUsize::new(0));
        Mock::given(method("POST"))
            .respond_with(CounterResponder { cc: call_count.clone() })
            .mount(&mock_server)
            .await;
        let handler = WebhookHandler::new(
            mock_server.uri(),
            Duration::from_secs(5),
            3,
        ).unwrap();
        let result = handler.send(vec![], DmarcPolicy::default()).await;
        assert!(result.is_ok());
    }
    #[tokio::test]
    async fn test_webhook_max_retries() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(500))
            .expect(4) // initial attempt + 3 retries
            .mount(&mock_server)
            .await;
        let handler = WebhookHandler::new(
            mock_server.uri(),
            Duration::from_secs(5),
            3,
        ).unwrap();
        let result = handler.send(vec![], DmarcPolicy::default()).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("failed after"));
    }
    #[tokio::test]
    async fn test_webhook_timeout() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_secs(2)))
            .mount(&mock_server)
            .await;
        let handler = WebhookHandler::new(
            mock_server.uri(),
            Duration::from_secs(1),
            1,
        ).unwrap();
        let result = handler.send(vec![], DmarcPolicy::default()).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("timeout"));
    }
    #[test]
    fn test_invalid_url() {
        let result = WebhookHandler::new(
            "not a url",
            Duration::from_secs(5),
            3,
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Invalid webhook URL"));
    }
}
