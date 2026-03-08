use std::net::IpAddr;
use std::time::Duration;

use chrono::{DateTime, Utc};
use nexus_common::{Decision, RequestContext};
use nexus_config::StoreConfig;
use sqlx::{PgPool, Postgres, QueryBuilder};
use tokio::sync::mpsc;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct BlockedEvent {
  pub id: Uuid,
  pub timestamp: DateTime<Utc>,
  pub client_ip: IpAddr,
  pub uri: String,
  pub method: String,
  pub risk_score: f32,
  pub decision: String,
  pub threat_tags: Vec<String>,
  pub blocked_by: Option<String>,
  pub ml_score: Option<f32>,
  pub ml_label: Option<String>,
  pub block_code: Option<String>,
}

impl BlockedEvent {
  /// Build from a RequestContext and its Decision.
  /// Call this after pipeline execution, never from inside a layer.
  pub fn from_context(ctx: &RequestContext, decision: &Decision) -> Self {
    let (decision_str, block_code) = match decision {
      Decision::Block { code, .. } => ("Block".to_string(), Some(format!("{code:?}"))),
      Decision::RateLimit { .. } => ("RateLimit".to_string(), None),
      Decision::Log { .. } => ("Log".to_string(), None),
      Decision::Allow => ("Allow".to_string(), None),
    };

    let mut threat_tags: Vec<String> = ctx.threat_tags.iter().cloned().collect();
    threat_tags.sort();

    Self {
      id: Uuid::new_v4(),
      timestamp: Utc::now(),
      client_ip: ctx.client_ip,
      uri: ctx.uri.clone(),
      method: ctx.method.0.as_str().to_string(),
      risk_score: ctx.risk_score,
      decision: decision_str,
      threat_tags,
      blocked_by: ctx.flagged_by.clone(),
      ml_score: ctx.ml_score,
      ml_label: ctx.ml_label.clone(),
      block_code,
    }
  }
}

/// Non-blocking async log writer.
///
/// - `record()` uses `try_send` and never blocks request processing.
/// - Background task batches and flushes to PostgreSQL by size or interval.
pub struct LogWriter {
  tx: mpsc::Sender<BlockedEvent>,
}

impl LogWriter {
  pub fn new(pool: PgPool, cfg: &StoreConfig) -> Self {
    let (tx, mut rx) = mpsc::channel::<BlockedEvent>(10_000);

    let batch_size = cfg.log_batch_size.max(1);
    let flush_ms = cfg.log_flush_ms.max(1);

    tokio::spawn(async move {
      let mut batch = Vec::with_capacity(batch_size);
      let mut interval = tokio::time::interval(Duration::from_millis(flush_ms));
      interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

      loop {
        tokio::select! {
          event = rx.recv() => {
            match event {
              Some(event) => {
                batch.push(event);
                if batch.len() >= batch_size {
                  flush_batch(&pool, &mut batch).await;
                }
              }
              None => {
                if !batch.is_empty() {
                  flush_batch(&pool, &mut batch).await;
                }
                break;
              }
            }
          }
          _ = interval.tick() => {
            if !batch.is_empty() {
              flush_batch(&pool, &mut batch).await;
            }
          }
        }
      }
    });

    Self { tx }
  }

  /// Non-blocking and loss-tolerant write path.
  pub fn record(&self, event: BlockedEvent) {
    if self.tx.try_send(event).is_err() {
      tracing::warn!("LogWriter channel full or closed - dropping event");
    }
  }
}

async fn flush_batch(pool: &PgPool, batch: &mut Vec<BlockedEvent>) {
  if batch.is_empty() {
    return;
  }

  let mut query_builder: QueryBuilder<'_, Postgres> = QueryBuilder::new(
    "INSERT INTO attack_logs \
     (id, timestamp, client_ip, uri, method, risk_score, decision, threat_tags, blocked_by, ml_score, ml_label, block_code) ",
  );

  query_builder.push_values(batch.iter(), |mut row, event| {
    row
      .push_bind(event.id)
      .push_bind(event.timestamp)
      // In push_values(), each `.push*()` is a value slot unless using the
      // `_unseparated` variants. Keep CAST(...) as a single SQL expression.
      .push_unseparated("CAST(")
      .push_bind_unseparated(event.client_ip.to_string())
      .push_unseparated(" AS INET)")
      .push_bind(event.uri.clone())
      .push_bind(event.method.clone())
      .push_bind(event.risk_score)
      .push_bind(event.decision.clone())
      .push_bind(event.threat_tags.clone())
      .push_bind(event.blocked_by.clone())
      .push_bind(event.ml_score)
      .push_bind(event.ml_label.clone())
      .push_bind(event.block_code.clone());
  });

  query_builder.push(" ON CONFLICT (id) DO NOTHING");

  let result = query_builder.build().execute(pool).await;
  match result {
    Ok(done) => {
      tracing::debug!(rows = done.rows_affected(), "Log batch flushed");
    }
    Err(error) => {
      tracing::warn!(
        error = %error,
        count = batch.len(),
        "Log batch flush failed - batch dropped"
      );
    }
  }

  batch.clear();
}

#[cfg(test)]
mod tests {
  use super::BlockedEvent;
  use bytes::Bytes;
  use http::{HeaderMap, Method, Uri, Version};
  use nexus_common::{BlockCode, Decision, RequestContext};
  use sqlx::{Execute, Postgres, QueryBuilder};
  use std::net::{IpAddr, Ipv4Addr};

  #[test]
  fn blocked_event_maps_context_fields() {
    let mut ctx = RequestContext::new(
      IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
      Method::POST,
      Uri::from_static("http://example.test/login?x=1"),
      Version::HTTP_11,
      HeaderMap::new(),
      Bytes::from_static(b"{}"),
    );

    ctx.add_risk(0.8);
    ctx.tag("sqli", "lexical");
    ctx.ml_score = Some(0.97);
    ctx.ml_label = Some("threat".to_string());

    let decision = Decision::block("attack detected", BlockCode::SqlInjection);
    let event = BlockedEvent::from_context(&ctx, &decision);

    assert_eq!(event.client_ip, ctx.client_ip);
    assert_eq!(event.uri, ctx.uri);
    assert_eq!(event.method, "POST");
    assert_eq!(event.decision, "Block");
    assert_eq!(event.block_code, Some("SqlInjection".to_string()));
    assert!(event.threat_tags.contains(&"sqli".to_string()));
    assert_eq!(event.blocked_by, Some("lexical".to_string()));
    assert_eq!(event.ml_score, Some(0.97));
    assert_eq!(event.ml_label, Some("threat".to_string()));
  }

  #[test]
  fn insert_builder_keeps_inet_cast_expression_valid() {
    let mut ctx = RequestContext::new(
      IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
      Method::GET,
      Uri::from_static("http://example.test/"),
      Version::HTTP_11,
      HeaderMap::new(),
      Bytes::new(),
    );
    ctx.tag("sqli", "rules");

    let decision = Decision::block("blocked", BlockCode::SqlInjection);
    let event = BlockedEvent::from_context(&ctx, &decision);

    let mut query_builder: QueryBuilder<'_, Postgres> = QueryBuilder::new(
      "INSERT INTO attack_logs \
       (id, timestamp, client_ip, uri, method, risk_score, decision, threat_tags, blocked_by, ml_score, ml_label, block_code) ",
    );

    query_builder.push_values(std::iter::once(&event), |mut row, event| {
      row
        .push_bind(event.id)
        .push_bind(event.timestamp)
        .push_unseparated("CAST(")
        .push_bind_unseparated(event.client_ip.to_string())
        .push_unseparated(" AS INET)")
        .push_bind(event.uri.clone())
        .push_bind(event.method.clone())
        .push_bind(event.risk_score)
        .push_bind(event.decision.clone())
        .push_bind(event.threat_tags.clone())
        .push_bind(event.blocked_by.clone())
        .push_bind(event.ml_score)
        .push_bind(event.ml_label.clone())
        .push_bind(event.block_code.clone());
    });

    let query = query_builder.build();
    let sql = query.sql();

    assert!(sql.contains("CAST($3 AS INET)"));
    assert!(!sql.contains("CAST(,"));
    assert!(!sql.contains(", AS INET"));
  }
}
