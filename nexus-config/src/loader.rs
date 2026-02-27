/// Loads and merges configuration from multiple sources in priority order:
///   1. Base TOML file (lowest priority)
///   2. Environment variable overrides (highest priority)
///
/// Environment variable naming convention:
///   NEXUS_<SECTION>_<KEY> (all uppercase, dots replaced with underscores)
///   e.g. NEXUS_GATEWAY_LISTEN_ADDR=0.0.0.0:8080
use crate::schema::Config;
use nexus_common::{NexusError, Result};
use std::path::Path;
use tracing::{info, warn};
pub struct ConfigLoader;

impl ConfigLoader {
  /// Load configuration from a TOML file path.
  pub fn from_file(path: impl AsRef<Path>) -> Result<Config> {
    let path = path.as_ref();
    info!(path = %path.display(), "Loading configuration");

    let content = std::fs::read_to_string(path).map_err(|e| {
      NexusError::Config(format!(
        "Failed to read config file '{}': {}",
        path.display(),
        e
      ))
    })?;

    Self::from_str(&content)
  }

  #[allow(clippy::should_implement_trait)]
  pub fn from_str(toml_str: &str) -> Result<Config> {
    let config: Config = toml::from_str(toml_str)
      .map_err(|e| NexusError::Config(format!("Failed to parse config TOML: {e}")))?;
    let config = Self::apply_env_overrides(config);
    config.validate()?;

    info!("Configuration loaded and validated successfully");
    Ok(config)
  }

  fn apply_env_overrides(mut config: Config) -> Config {
    if let Ok(v) = std::env::var("NEXUS_GATEWAY_LISTEN_ADDR") {
      info!(value = %v, "ENV override: gateway.listen_addr");
      config.gateway.listen_addr = v;
    }
    if let Ok(v) = std::env::var("NEXUS_GATEWAY_CONTROL_ADDR") {
      info!(value = %v, "ENV override: gateway.control_addr");
      config.gateway.control_addr = v;
    }
    if let Ok(v) = std::env::var("NEXUS_GATEWAY_METRICS_ADDR") {
      info!(value = %v, "ENV override: gateway.metrics_addr");
      config.gateway.metrics_addr = v;
    }
    if let Ok(v) = std::env::var("NEXUS_GATEWAY_MAX_BODY_BYTES") {
      if let Ok(n) = v.parse() {
        config.gateway.max_body_bytes = n;
      } else {
        warn!(value = %v, "Invalid value for NEXUS_GATEWAY_MAX_BODY_BYTES, ignoring");
      }
    }

    if let Ok(v) = std::env::var("NEXUS_RATE_REQUESTS_PER_SECOND") {
      if let Ok(n) = v.parse() {
        config.rate.requests_per_second = n;
      }
    }
    if let Ok(v) = std::env::var("NEXUS_RATE_BURST_CAPACITY") {
      if let Ok(n) = v.parse() {
        config.rate.burst_capacity = n;
      }
    }
    if let Ok(v) = std::env::var("NEXUS_RATE_ENABLED") {
      config.rate.enabled = v.to_lowercase() != "false" && v != "0";
    }

    if let Ok(v) = std::env::var("NEXUS_ML_ENDPOINT") {
      info!(value = %v, "ENV override: ml.endpoint");
      config.ml.endpoint = v;
    }
    if let Ok(v) = std::env::var("NEXUS_ML_TIMEOUT_MS") {
      if let Ok(n) = v.parse() {
        config.ml.timeout_ms = n;
      }
    }

    if let Ok(v) = std::env::var("NEXUS_PIPELINE_ML_ENABLED") {
      config.pipeline.ml_enabled = v.to_lowercase() != "false" && v != "0";
    }
    if let Ok(v) = std::env::var("NEXUS_PIPELINE_RISK_THRESHOLD") {
      if let Ok(n) = v.parse::<f32>() {
        config.pipeline.risk_threshold = n;
      }
    }

    config
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  const MINIMAL_CONFIG: &str = r#"
[gateway]
listen_addr   = "0.0.0.0:8080"
control_addr  = "0.0.0.0:9090"
metrics_addr  = "0.0.0.0:9091"

[pipeline]

[rate]

[lexical]

[lb]
upstreams = [
    { name = "backend-1", addr = "127.0.0.1:3000" }
]

[rules]
rules_file = "config/rules.toml"
"#;

  #[test]
  fn loads_minimal_config() {
    let cfg = ConfigLoader::from_str(MINIMAL_CONFIG).expect("valid config");
    assert_eq!(cfg.gateway.listen_addr, "0.0.0.0:8080");
    assert_eq!(cfg.lb.upstreams.len(), 1);
    assert_eq!(cfg.lb.upstreams[0].name, "backend-1");
  }

  #[test]
  fn defaults_are_sane() {
    let cfg = ConfigLoader::from_str(MINIMAL_CONFIG).unwrap();
    assert_eq!(cfg.gateway.max_body_bytes, 1024 * 1024);
    assert_eq!(cfg.rate.requests_per_second, 1000);
    assert!(cfg.pipeline.ml_enabled);
    assert!(cfg.rate.enabled);
  }

  #[test]
  fn validation_rejects_empty_listen_addr() {
    let bad = MINIMAL_CONFIG.replace("\"0.0.0.0:8080\"", "\"\"");
    assert!(ConfigLoader::from_str(&bad).is_err());
  }

  #[test]
  fn validation_rejects_no_upstreams() {
    let bad = MINIMAL_CONFIG.replace(
      "upstreams = [\n    { name = \"backend-1\", addr = \"127.0.0.1:3000\" }\n]",
      "upstreams = []",
    );
    assert!(ConfigLoader::from_str(&bad).is_err());
  }
}
