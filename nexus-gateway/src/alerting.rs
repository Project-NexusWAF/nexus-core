use std::sync::Arc;
use std::time::Duration;

use nexus_config::{LiveConfig, SlackSeverity};
use nexus_store::BlockedEvent;
use serde::Serialize;
use tokio::sync::mpsc;

#[derive(Debug, Clone)]
pub enum AlertMessage {
  Blocked(BlockedEvent),
  System {
    title: String,
    body: String,
    severity: SlackSeverity,
  },
}

pub struct SlackAlertSender {
  tx: mpsc::Sender<AlertMessage>,
}

impl SlackAlertSender {
  pub fn new(live_config: LiveConfig) -> Arc<Self> {
    let (tx, mut rx) = mpsc::channel::<AlertMessage>(2048);
    tokio::spawn(async move {
      let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("slack client must build");

      while let Some(message) = rx.recv().await {
        let cfg = live_config.borrow().clone();
        if !cfg.slack.enabled || cfg.slack.webhook_url.trim().is_empty() {
          continue;
        }

        let payload = match build_payload(&cfg.slack, &message) {
          Some(payload) => payload,
          None => continue,
        };

        match client.post(&cfg.slack.webhook_url).json(&payload).send().await {
          Ok(response) if response.status().is_success() => {}
          Ok(response) => {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            tracing::warn!(status = %status, body = %body, "Slack webhook rejected alert");
          }
          Err(error) => {
            tracing::warn!(error = %error, "failed to send Slack alert");
          }
        }
      }
    });

    Arc::new(Self { tx })
  }

  pub fn record_blocked(&self, event: BlockedEvent) {
    if self.tx.try_send(AlertMessage::Blocked(event)).is_err() {
      tracing::warn!("Slack alert channel full or closed - dropping alert");
    }
  }

  pub fn notify_system(
    &self,
    title: impl Into<String>,
    body: impl Into<String>,
    severity: SlackSeverity,
  ) {
    let message = AlertMessage::System {
      title: title.into(),
      body: body.into(),
      severity,
    };
    if self.tx.try_send(message).is_err() {
      tracing::warn!("Slack alert channel full or closed - dropping system alert");
    }
  }
}

#[derive(Serialize)]
struct SlackPayload {
  text: String,
  #[serde(skip_serializing_if = "String::is_empty")]
  channel: String,
  #[serde(skip_serializing_if = "String::is_empty")]
  username: String,
  #[serde(skip_serializing_if = "String::is_empty")]
  icon_emoji: String,
}

fn build_payload(cfg: &nexus_config::SlackConfig, message: &AlertMessage) -> Option<SlackPayload> {
  let text = match message {
    AlertMessage::Blocked(event) => {
      if event.decision == "RateLimit" && !cfg.include_rate_limits {
        return None;
      }
      let severity = classify_event(event);
      if severity < cfg.min_severity {
        return None;
      }
      let tags = if event.threat_tags.is_empty() {
        "none".to_string()
      } else {
        event.threat_tags.join(", ")
      };
      let blocked_by = event.blocked_by.clone().unwrap_or_else(|| "unknown".to_string());
      format!(
        "[{severity:?}] NexusWAF event\nDecision: {}\nBlocked by: {}\nIP: {}\nMethod: {}\nURI: {}\nTags: {}\nRisk: {:.2}",
        event.decision,
        blocked_by,
        event.client_ip,
        event.method,
        event.uri,
        tags,
        event.risk_score
      )
    }
    AlertMessage::System {
      title,
      body,
      severity,
    } => {
      if *severity < cfg.min_severity {
        return None;
      }
      format!("[{severity:?}] {title}\n{body}")
    }
  };

  Some(SlackPayload {
    text,
    channel: cfg.channel.clone(),
    username: cfg.username.clone(),
    icon_emoji: cfg.icon_emoji.clone(),
  })
}

fn classify_event(event: &BlockedEvent) -> SlackSeverity {
  if matches!(
    event.block_code.as_deref(),
    Some("CommandInjection") | Some("SqlInjection")
  ) {
    return SlackSeverity::Critical;
  }
  if matches!(
    event.block_code.as_deref(),
    Some("CrossSiteScripting") | Some("PathTraversal") | Some("MlDetectedThreat")
  ) {
    return SlackSeverity::High;
  }
  if matches!(
    event.block_code.as_deref(),
    Some("ProtocolViolation") | Some("MalformedPayload")
  ) {
    return SlackSeverity::Medium;
  }
  if event.decision == "Block" {
    return SlackSeverity::Medium;
  }
  if event.decision == "RateLimit" || event.threat_tags.iter().any(|tag| tag == "anomaly") {
    return SlackSeverity::Medium;
  }
  SlackSeverity::Low
}

#[cfg(test)]
mod tests {
  use super::classify_event;
  use chrono::Utc;
  use nexus_config::SlackSeverity;
  use nexus_store::BlockedEvent;
  use std::net::{IpAddr, Ipv4Addr};
  use uuid::Uuid;

  fn sample_event(decision: &str, block_code: Option<&str>) -> BlockedEvent {
    BlockedEvent {
      id: Uuid::new_v4(),
      timestamp: Utc::now(),
      client_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
      uri: "/search?q=test".to_string(),
      method: "GET".to_string(),
      risk_score: 0.7,
      decision: decision.to_string(),
      threat_tags: vec![],
      blocked_by: Some("pipeline".to_string()),
      ml_score: None,
      ml_label: None,
      block_code: block_code.map(str::to_string),
    }
  }

  #[test]
  fn protocol_violation_blocks_are_medium() {
    let event = sample_event("Block", Some("ProtocolViolation"));
    assert_eq!(classify_event(&event), SlackSeverity::Medium);
  }

  #[test]
  fn generic_blocks_default_to_medium() {
    let event = sample_event("Block", None);
    assert_eq!(classify_event(&event), SlackSeverity::Medium);
  }
}
