use futures::stream;
use influxdb2::models::DataPoint;
use influxdb2::Client;
use nexus_config::StoreConfig;

pub struct MetricsSnapshot {
  pub requests_total: u64,
  pub blocked_total: u64,
  pub rate_limited_total: u64,
  pub avg_latency_us: f64,
}

pub struct MetricsWriter {
  client: Option<Client>,
  org: String,
  bucket: String,
}

impl MetricsWriter {
  pub fn new(cfg: &StoreConfig) -> Self {
    let client = if cfg.influx_token.trim().is_empty() {
      None
    } else {
      Some(Client::new(
        &cfg.influx_url,
        &cfg.influx_org,
        &cfg.influx_token,
      ))
    };

    Self {
      client,
      org: cfg.influx_org.clone(),
      bucket: cfg.influx_bucket.clone(),
    }
  }

  pub fn is_enabled(&self) -> bool {
    self.client.is_some()
  }

  pub async fn write_snapshot(&self, snap: MetricsSnapshot) {
    let Some(client) = &self.client else {
      return;
    };

    let point = DataPoint::builder("waf_metrics")
      .field("requests_total", snap.requests_total as i64)
      .field("blocked_total", snap.blocked_total as i64)
      .field("rate_limited_total", snap.rate_limited_total as i64)
      .field("avg_latency_us", snap.avg_latency_us)
      .build();

    match point {
      Ok(point) => {
        if let Err(error) = client.write(&self.bucket, stream::iter([point])).await {
          tracing::warn!(
            error = %error,
            org = %self.org,
            bucket = %self.bucket,
            "InfluxDB write failed - metrics may be missing"
          );
        }
      }
      Err(error) => {
        tracing::warn!(error = %error, "Failed to build InfluxDB data point");
      }
    }
  }
}

#[cfg(test)]
mod tests {
  use super::{MetricsSnapshot, MetricsWriter};
  use nexus_config::StoreConfig;

  #[tokio::test]
  async fn no_op_when_token_is_empty() {
    let cfg = StoreConfig {
      influx_token: String::new(),
      ..StoreConfig::default()
    };

    let writer = MetricsWriter::new(&cfg);
    assert!(!writer.is_enabled());

    writer
      .write_snapshot(MetricsSnapshot {
        requests_total: 10,
        blocked_total: 1,
        rate_limited_total: 2,
        avg_latency_us: 1234.0,
      })
      .await;
  }
}
