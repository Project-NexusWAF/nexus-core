use std::sync::Arc;
use std::time::Instant;

use crate::metrics_placeholder::MetricsRegistry;
use nexus_common::{BlockCode, Decision, Layer, RequestContext, Result};
use tracing::{debug, info, warn};

use crate::run_result::{LayerTiming, RunResult};

#[derive(Clone)]
pub struct Pipeline {
  layers: Arc<Vec<Layer>>,
  risk_threshold: f32,
}

impl Pipeline {
  pub(crate) fn new(layers: Vec<Layer>, risk_threshold: f32) -> Self {
    Self {
      layers: Arc::new(layers),
      risk_threshold,
    }
  }

  pub fn layer_names(&self) -> Vec<&'static str> {
    self.layers.iter().map(|layer| layer.name()).collect()
  }

  pub async fn init(&self) -> Result<()> {
    for layer in self.layers.iter() {
      layer.init().await?;
      debug!(layer = layer.name(), "Layer initialised");
    }
    info!(layer_count = self.layers.len(), "Pipeline initialised");
    Ok(())
  }

  pub async fn run(&self, ctx: &mut RequestContext) -> RunResult {
    let pipeline_start = Instant::now();
    let mut timings = Vec::with_capacity(self.layers.len());
    let mut final_decision = Decision::Allow;
    let mut decided_by = None;

    for layer in self.layers.iter() {
      let layer_start = Instant::now();

      let decision = match layer.analyse(ctx).await {
        Ok(decision) => decision,
        Err(error) => {
          warn!(
            layer = layer.name(),
            error = %error,
            request_id = %ctx.id,
            "Layer analysis failed; failing open"
          );
          Decision::Allow
        }
      };

      let layer_duration = layer_start.elapsed();
      MetricsRegistry::record_layer(layer.name(), layer_duration.as_micros() as f64);
      if matches!(decision, Decision::RateLimit { .. }) {
        MetricsRegistry::record_rate_limit();
      }

      timings.push(LayerTiming {
        name: layer.name(),
        duration: layer_duration,
        decision: decision.clone(),
      });

      if decision.is_blocking() {
        if let Decision::Block { code, .. } = &decision {
          MetricsRegistry::record_block(layer.name(), &format!("{code:?}"));
        }
        decided_by = Some(layer.name());
        final_decision = decision;
        break;
      }

      if ctx.risk_score >= self.risk_threshold {
        final_decision = Decision::block(
          format!("Risk threshold exceeded: {:.2}", ctx.risk_score),
          BlockCode::ProtocolViolation,
        );
        decided_by = Some(layer.name());
        MetricsRegistry::record_block(layer.name(), "RiskThreshold");
        break;
      }

      final_decision = final_decision.merge(decision);
    }

    let total_duration = pipeline_start.elapsed();
    MetricsRegistry::record_request(
      ctx.method.0.as_str(),
      decision_label(&final_decision),
      total_duration.as_secs_f64() * 1_000.0,
    );

    RunResult {
      decision: final_decision,
      timings,
      total_duration,
      decided_by,
      final_risk_score: ctx.risk_score,
    }
  }
}

fn decision_label(decision: &Decision) -> &'static str {
  match decision {
    Decision::Allow => "allow",
    Decision::Block { .. } => "block",
    Decision::Log { .. } => "log",
    Decision::RateLimit { .. } => "rate_limit",
  }
}

#[cfg(test)]
mod tests {
  use std::net::{IpAddr, Ipv4Addr};

  use super::*;
  use crate::builder::PipelineBuilder;
  use async_trait::async_trait;
  use bytes::Bytes;
  use http::{HeaderMap, Method, Version};
  use nexus_common::{InnerLayer, NexusError};
  use nexus_config::ConfigLoader;

  enum TestBehavior {
    Allow,
    Block,
    AddRisk(f32),
    Err,
  }

  struct TestLayer {
    name: &'static str,
    priority: u8,
    behavior: TestBehavior,
  }

  impl TestLayer {
    fn new(name: &'static str, priority: u8, behavior: TestBehavior) -> Self {
      Self {
        name,
        priority,
        behavior,
      }
    }
  }

  #[async_trait]
  impl InnerLayer for TestLayer {
    fn name(&self) -> &'static str {
      self.name
    }

    fn priority(&self) -> u8 {
      self.priority
    }

    async fn analyse(&self, ctx: &mut RequestContext) -> Result<Decision> {
      match self.behavior {
        TestBehavior::Allow => Ok(Decision::Allow),
        TestBehavior::Block => Ok(Decision::block(
          "blocked by test layer",
          BlockCode::Custom("test".to_string()),
        )),
        TestBehavior::AddRisk(delta) => {
          ctx.add_risk(delta);
          Ok(Decision::Allow)
        }
        TestBehavior::Err => Err(NexusError::Internal("test layer error".to_string())),
      }
    }
  }

  fn make_ctx() -> RequestContext {
    RequestContext::new(
      IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
      Method::GET,
      "http://example.com/test".parse().unwrap(),
      Version::HTTP_11,
      HeaderMap::new(),
      Bytes::new(),
    )
  }

  #[tokio::test]
  async fn clean_request_returns_allow() {
    let pipeline = PipelineBuilder::new()
      .layer(Box::new(TestLayer::new("a", 10, TestBehavior::Allow)))
      .layer(Box::new(TestLayer::new("b", 20, TestBehavior::Allow)))
      .build();

    let mut ctx = make_ctx();
    let result = pipeline.run(&mut ctx).await;

    assert_eq!(result.decision, Decision::Allow);
    assert_eq!(result.timings.len(), 2);
    assert_eq!(result.decided_by, None);
  }

  #[tokio::test]
  async fn blocking_layer_short_circuits() {
    let pipeline = PipelineBuilder::new()
      .layer(Box::new(TestLayer::new("allow", 10, TestBehavior::Allow)))
      .layer(Box::new(TestLayer::new("blocker", 20, TestBehavior::Block)))
      .layer(Box::new(TestLayer::new(
        "never-run",
        30,
        TestBehavior::Allow,
      )))
      .build();

    let mut ctx = make_ctx();
    let result = pipeline.run(&mut ctx).await;

    assert!(result.decision.is_blocking());
    assert_eq!(result.decided_by, Some("blocker"));
    assert_eq!(result.timings.len(), 2);
  }

  #[tokio::test]
  async fn risk_threshold_blocks_even_when_layers_allow() {
    let pipeline = PipelineBuilder::new()
      .risk_threshold(0.7)
      .layer(Box::new(TestLayer::new(
        "risk-a",
        10,
        TestBehavior::AddRisk(0.4),
      )))
      .layer(Box::new(TestLayer::new(
        "risk-b",
        20,
        TestBehavior::AddRisk(0.4),
      )))
      .layer(Box::new(TestLayer::new(
        "never-run",
        30,
        TestBehavior::Allow,
      )))
      .build();

    let mut ctx = make_ctx();
    let result = pipeline.run(&mut ctx).await;

    assert!(matches!(result.decision, Decision::Block { .. }));
    assert_eq!(result.decided_by, Some("risk-b"));
    assert_eq!(result.timings.len(), 2);
    assert!(result.final_risk_score >= 0.7);
  }

  #[tokio::test]
  async fn layer_error_is_fail_open_and_pipeline_continues() {
    let pipeline = PipelineBuilder::new()
      .layer(Box::new(TestLayer::new("err", 10, TestBehavior::Err)))
      .layer(Box::new(TestLayer::new("allow", 20, TestBehavior::Allow)))
      .build();

    let mut ctx = make_ctx();
    let result = pipeline.run(&mut ctx).await;

    assert_eq!(result.decision, Decision::Allow);
    assert_eq!(result.timings.len(), 2);
    assert_eq!(result.decided_by, None);
  }

  #[tokio::test]
  async fn builder_sorts_layers_by_priority() {
    let pipeline = PipelineBuilder::new()
      .layer(Box::new(TestLayer::new("third", 30, TestBehavior::Allow)))
      .layer(Box::new(TestLayer::new("first", 10, TestBehavior::Allow)))
      .layer(Box::new(TestLayer::new("second", 20, TestBehavior::Allow)))
      .build();

    assert_eq!(pipeline.layer_names(), vec!["first", "second", "third"]);
  }

  #[tokio::test]
  async fn empty_pipeline_returns_allow() {
    let pipeline = PipelineBuilder::new().build();
    let mut ctx = make_ctx();
    let result = pipeline.run(&mut ctx).await;

    assert_eq!(result.decision, Decision::Allow);
    assert_eq!(result.timings.len(), 0);
    assert_eq!(result.decided_by, None);
  }

  #[test]
  fn from_config_with_missing_rules_file_builds_without_rules_layer() {
    let cfg = ConfigLoader::from_str(
      r#"
[gateway]
listen_addr = "0.0.0.0:8080"
control_addr = "0.0.0.0:9090"
metrics_addr = "0.0.0.0:9091"

[pipeline]
risk_threshold = 0.7
ml_enabled = true
short_circuit = true

[rate]
enabled = true
requests_per_second = 1000
burst_capacity = 200
window_secs = 1
cleanup_interval_secs = 300

[lexical]
sqli_enabled = true
xss_enabled = true
path_traversal_enabled = true
cmd_injection_enabled = true
risk_delta = 0.4
block_on_match = false

[lb]
algorithm = "round_robin"
health_check_interval_secs = 10
unhealthy_threshold = 3
healthy_threshold = 2
upstreams = [
  { name = "backend-1", addr = "127.0.0.1:3000", weight = 1, enabled = true }
]

[rules]
rules_file = "this/path/does/not/exist.toml"
fail_closed = true

[ml]
endpoint = "http://127.0.0.1:50051"
timeout_ms = 10000
risk_delta = 0.6
confidence_threshold = 0.8
"#,
    )
    .expect("config should parse");

    let pipeline = PipelineBuilder::from_config(&cfg);
    let names = pipeline.layer_names();

    assert!(names.contains(&"rate"));
    assert!(names.contains(&"lexical"));
    assert!(names.contains(&"grammar"));
    assert!(names.contains(&"ml"));
    assert!(!names.contains(&"rules"));
  }
}
