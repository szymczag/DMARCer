//! Worker Module for DMARCer
//!
//! This worker continuously consumes tasks from a RabbitMQ queue, downloads a DMARC report file,
//! processes it, and stores the results in PostgreSQL using parameterized queries (to prevent SQL injection).
//! Finally, it publishes a notification via Redis Pub/Sub.
//!
//! **Important:**  
//! - Ensure that the environment variable `DATABASE_URL` is set (or run `cargo sqlx prepare`) so that
//!   SQLX's compile‑time query checking works.  
//! - The worker uses `get_multiplexed_async_connection` for Redis to avoid deprecation warnings.

use anyhow::Result;
use futures_util::stream::StreamExt;
use lapin::{
    options::{BasicAckOptions, BasicConsumeOptions, QueueDeclareOptions},
    types::FieldTable,
    Connection, ConnectionProperties,
};
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::env;
use tokio;

use dmarcer::{parse_dmarc_xml};
use dmarcer::models::DmarcRecord;

/// Message format for tasks received from the MQ.
#[derive(Debug, Serialize, Deserialize)]
struct TaskMessage {
    task_id: String,
    file_path: String,
    organization_id: String,
    domain: String,
    original_filename: String,
}

/// Downloads the DMARC report file from storage.
///
/// For demonstration purposes, this simply reads the file from a local path.
/// In a production environment, integrate with a MinIO/S3 client.
async fn download_file(file_path: &str) -> Result<String> {
    let content = tokio::fs::read_to_string(file_path).await?;
    Ok(content)
}

/// Processes the DMARC report file and returns the extracted DMARC records.
///
/// In this mode, the output is JSON-only (raw DMARC records) for further processing.
async fn process_report(file_content: &str) -> Result<Vec<DmarcRecord>> {
    // For compressed files, you would call extract_zip first.
    // Here, we assume file_content is the XML report.
    let (records, _policy) = parse_dmarc_xml(file_content)?;
    Ok(records)
}

/// Inserts the extracted DMARC records into PostgreSQL using a parameterized query.
/// This example uses the `sqlx::query!` macro, which requires that `DATABASE_URL` is set
/// or that you run `cargo sqlx prepare` to update the query cache.
async fn insert_records_to_postgres(
    pool: &PgPool,
    task_id: &str,
    records: &[DmarcRecord],
) -> Result<()> {
    for record in records {
        sqlx::query!(
            r#"
            INSERT INTO report_records (
                report_id,
                source_ip,
                count,
                policy_disposition,
                dkim_result,
                spf_result,
                header_from,
                raw_data
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            "#,
            task_id,
            record.source_ip,
            record.count as i32,
            record.policy_evaluated.disposition,
            serde_json::to_string(&record.dkim)?,
            format!("{}", record.spf.result),
            record.header_from,
            serde_json::to_value(record)?
        )
        .execute(pool)
        .await?;
    }
    Ok(())
}

/// Publishes a notification on Redis Pub/Sub with the given task_id.
/// 
/// Uses get_multiplexed_async_connection and explicitly annotates the publish call.
async fn publish_notification(redis_client: &redis::Client, task_id: &str) -> Result<()> {
    let mut conn = redis_client.get_multiplexed_async_connection().await?;
    // Explicitly specify the types for the publish method.
    conn.publish::<&str, &str, ()>("dmarc_notifications", task_id).await?;
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    // Load configuration from environment variables.
    let amqp_addr = env::var("AMQP_ADDR").unwrap_or_else(|_| "amqp://127.0.0.1:5672/%2f".into());
    let database_url = env::var("DATABASE_URL")?;
    let redis_url = env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1/".into());

    // Connect to RabbitMQ.
    let conn = Connection::connect(&amqp_addr, ConnectionProperties::default()).await?;
    let channel = conn.create_channel().await?;
    channel
        .queue_declare(
            "dmarc_processing",
            QueueDeclareOptions::default(),
            FieldTable::default(),
        )
        .await?;
    let mut consumer = channel
        .basic_consume(
            "dmarc_processing",
            "dmarc_consumer",
            BasicConsumeOptions::default(),
            FieldTable::default(),
        )
        .await?;

    // Set up PostgreSQL connection pool.
    let pg_pool = PgPool::connect(&database_url).await?;

    // Set up Redis client.
    let redis_client = redis::Client::open(redis_url)?;

    println!("Worker started, waiting for messages...");

    // Process messages continuously.
    while let Some(delivery_result) = consumer.next().await {
        match delivery_result {
            Ok(delivery) => {
                // Deserialize the task message.
                let task_msg: TaskMessage = serde_json::from_slice(&delivery.data)?;
                println!("Processing task: {}", task_msg.task_id);

                // Download the DMARC report file.
                let file_content = download_file(&task_msg.file_path).await?;

                // Process the report.
                let records = process_report(&file_content).await?;

                // Insert records into PostgreSQL.
                insert_records_to_postgres(&pg_pool, &task_msg.task_id, &records).await?;

                // Publish a notification.
                publish_notification(&redis_client, &task_msg.task_id).await?;

                // Acknowledge the message.
                delivery.ack(BasicAckOptions::default()).await?;
            }
            Err(e) => {
                eprintln!("Error receiving message: {:?}", e);
            }
        }
    }

    Ok(())
}
