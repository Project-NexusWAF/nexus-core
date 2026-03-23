use async_trait::async_trait;

use crate::client::MlClient;
use nexus_metrics::MetricsRegistry;

pub struct MlLayer {
  client: MlClient,
  risk_delta: f32,
  confidence_threshold: f32,
  enabled: bool,
}

impl MlLayer {
  pub fn from_config(
    ml_cfg: &nexus_config::MlConfig,
    pipeline_cfg: &nexus_config::PipelineConfig,
  ) -> Self {
    Self {
      client: MlClient::from_config(ml_cfg),
      risk_delta: ml_cfg.risk_delta,
      confidence_threshold: ml_cfg.confidence_threshold,
      enabled: pipeline_cfg.ml_enabled,
    }
  }
}

#[async_trait]
impl nexus_common::InnerLayer for MlLayer {
  fn name(&self) -> &'static str {
    "ml"
  }

  fn priority(&self) -> u8 {
    40
  }

  async fn init(&self) -> nexus_common::Result<()> {
    tracing::info!(
      endpoint = %self.client.endpoint(),
      enabled = self.enabled,
      "ML layer initialised"
    );
    Ok(())
  }

  async fn analyse(
    &self,
    ctx: &mut nexus_common::RequestContext,
  ) -> nexus_common::Result<nexus_common::Decision> {
    if !self.enabled {
      return Ok(nexus_common::Decision::Allow);
    }

    let result = self.client.classify(ctx).await;
    MetricsRegistry::record_ml(result.duration.as_secs_f64() * 1_000.0, Some(&result.label));

    ctx.ml_score = Some(result.score);
    ctx.ml_label = Some(result.label.clone());

    if result.is_threat(self.confidence_threshold) {
      ctx.tag(&result.label, self.name());
      ctx.add_risk(self.risk_delta);
    }

    Ok(nexus_common::Decision::Allow)
  }
}
