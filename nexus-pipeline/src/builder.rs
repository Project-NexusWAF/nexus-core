use nexus_common::Layer;
use nexus_config::Config;
use nexus_grammar::GrammarLayer;
use nexus_lex::LexicalLayer;
use nexus_ml_client::MlLayer;
use nexus_rate::RateLayer;
use nexus_rules::{RuleEngine, RuleLayer, RuleSet};
use tracing::warn;

use crate::pipeline::Pipeline;

pub struct PipelineBuilder {
  layers: Vec<Layer>,
  risk_threshold: f32,
}

impl PipelineBuilder {
  pub fn new() -> Self {
    Self {
      layers: Vec::new(),
      risk_threshold: 0.7,
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

  pub fn build(mut self) -> Pipeline {
    self.layers.sort_by_key(|layer| layer.priority());
    Pipeline::new(self.layers, self.risk_threshold)
  }

  pub fn from_config(cfg: &Config) -> Pipeline {
    let mut builder = Self::new().risk_threshold(cfg.pipeline.risk_threshold);

    builder = builder.layer(Box::new(RateLayer::from_config(&cfg.rate)));
    builder = builder.layer(Box::new(LexicalLayer::from_config(&cfg.lexical)));
    builder = builder.layer(Box::new(GrammarLayer::from_config(&cfg.lexical)));

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

    builder = builder.layer(Box::new(MlLayer::from_config(&cfg.ml, &cfg.pipeline)));
    builder.build()
  }
}

impl Default for PipelineBuilder {
  fn default() -> Self {
    Self::new()
  }
}
