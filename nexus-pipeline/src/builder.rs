use std::sync::Arc;

use nexus_anomaly::{AnomalyLayer, AnomalyState};
use nexus_common::Layer;
use nexus_config::Config;
use nexus_grammar::GrammarLayer;
use nexus_lex::LexicalLayer;
use nexus_ml_client::MlLayer;
use nexus_policy::PolicyLayer;
use nexus_rate::RateLayer;
use nexus_rules::{RuleEngine, RuleLayer, RuleSet};
use nexus_telemetry::PolicyTelemetry;
use tracing::warn;

use crate::pipeline::Pipeline;

pub struct PipelineBuilder {
  layers: Vec<Layer>,
  risk_threshold: f32,
  telemetry: Arc<PolicyTelemetry>,
  anomaly_state: Arc<AnomalyState>,
}

impl PipelineBuilder {
  pub fn new() -> Self {
    Self {
      layers: Vec::new(),
      risk_threshold: 0.7,
      telemetry: Arc::new(PolicyTelemetry::new()),
      anomaly_state: Arc::new(AnomalyState::new()),
    }
  }

  pub fn layer(mut self, layer: Layer) -> Self {
    self.layers.push(layer);
    self
  }

  pub fn risk_threshold(mut self, threshold: f32) -> Self {
    self.risk_threshold = threshold;
    self
  }

  pub fn telemetry(mut self, telemetry: Arc<PolicyTelemetry>) -> Self {
    self.telemetry = telemetry;
    self
  }

  pub fn anomaly_state(mut self, state: Arc<AnomalyState>) -> Self {
    self.anomaly_state = state;
    self
  }

  pub fn build(mut self) -> Pipeline {
    self.layers.sort_by_key(|layer| layer.priority());
    Pipeline::new(
      self.layers,
      self.risk_threshold,
      self.telemetry,
      self.anomaly_state,
    )
  }

  pub fn from_config(cfg: &Config) -> Pipeline {
    Self::from_config_with_state(
      cfg,
      Arc::new(PolicyTelemetry::new()),
      Arc::new(AnomalyState::new()),
    )
  }

  pub fn from_config_with_state(
    cfg: &Config,
    telemetry: Arc<PolicyTelemetry>,
    anomaly_state: Arc<AnomalyState>,
  ) -> Pipeline {
    let mut builder = Self::new()
      .risk_threshold(cfg.pipeline.risk_threshold)
      .telemetry(Arc::clone(&telemetry))
      .anomaly_state(Arc::clone(&anomaly_state));

    builder = builder.layer(Box::new(RateLayer::from_config(&cfg.rate)));
    builder = builder.layer(Box::new(LexicalLayer::from_config(&cfg.lexical)));
    builder = builder.layer(Box::new(GrammarLayer::from_config(&cfg.lexical)));

    if cfg.anomaly.enabled {
      builder = builder.layer(Box::new(AnomalyLayer::from_config(
        &cfg.anomaly,
        Arc::clone(&anomaly_state),
      )));
    }

    match RuleSet::from_file(&cfg.rules.rules_file) {
      Ok(ruleset) => {
        let engine = RuleEngine::new(ruleset);
        builder = builder.layer(Box::new(RuleLayer::new(engine)));
      }
      Err(error) => {
        warn!(
          error = %error,
          rules_file = %cfg.rules.rules_file,
          "Rules layer unavailable; continuing without rules"
        );
      }
    }

    if cfg.policy.enabled {
      builder = builder.layer(Box::new(PolicyLayer::from_config(
        &cfg.policy,
        &cfg.pipeline,
        Arc::clone(&telemetry),
      )));
    }

    builder = builder.layer(Box::new(MlLayer::from_config(&cfg.ml, &cfg.pipeline)));
    builder.build()
  }
}

impl Default for PipelineBuilder {
  fn default() -> Self {
    Self::new()
  }
}
