use std::sync::Arc;

use tonic::{Request, Response, Status};

use crate::ops;
use crate::proto::control_plane_server::ControlPlane;
use crate::proto::{
  GetRulesRequest, GetRulesResponse, GetStatsRequest, HealthCheckRequest, HealthCheckResponse,
  ListRuleVersionsRequest, ListRuleVersionsResponse, RuleVersion, StatsResponse,
  UpdateRulesRequest, UpdateRulesResponse,
};
use crate::ControlAppState;

pub struct ControlServer {
  state: Arc<ControlAppState>,
}

impl ControlServer {
  pub fn new(state: Arc<ControlAppState>) -> Self {
    Self { state }
  }
}

#[tonic::async_trait]
impl ControlPlane for ControlServer {
  async fn health_check(
    &self,
    _request: Request<HealthCheckRequest>,
  ) -> Result<Response<HealthCheckResponse>, Status> {
    let health = ops::health_snapshot(&self.state);
    Ok(Response::new(HealthCheckResponse {
      ok: health.ok,
      status: health.status.to_string(),
      config_version: health.config_version,
    }))
  }

  async fn get_stats(
    &self,
    _request: Request<GetStatsRequest>,
  ) -> Result<Response<StatsResponse>, Status> {
    let stats = ops::stats_snapshot(&self.state);
    Ok(Response::new(StatsResponse {
      requests_total: stats.requests_total,
      blocked_total: stats.blocked_total,
      rate_limited_total: stats.rate_limited_total,
      pipeline_layers: stats
        .pipeline_layers
        .into_iter()
        .map(str::to_string)
        .collect(),
      config_version: stats.config_version,
      ml_circuit_state: stats.ml_circuit_state,
      healthy_upstreams: stats.healthy_upstreams as u64,
    }))
  }

  async fn get_rules(
    &self,
    _request: Request<GetRulesRequest>,
  ) -> Result<Response<GetRulesResponse>, Status> {
    let rules = ops::get_rules(&self.state)
      .await
      .map_err(|e| Status::internal(e.to_string()))?;
    Ok(Response::new(GetRulesResponse {
      found: rules.found,
      version: rules.version,
      content: rules.content,
      source: rules.source,
    }))
  }

  async fn update_rules(
    &self,
    request: Request<UpdateRulesRequest>,
  ) -> Result<Response<UpdateRulesResponse>, Status> {
    let payload = request.into_inner();
    let version = payload.version.trim();
    let content = payload.content.trim();
    if version.is_empty() || content.is_empty() {
      return Err(Status::invalid_argument(
        "version and content must both be non-empty",
      ));
    }

    let config_version = ops::update_rules(&self.state, version, content)
      .await
      .map_err(|e| Status::invalid_argument(e.to_string()))?;

    Ok(Response::new(UpdateRulesResponse {
      updated: true,
      config_version,
      message: "rules updated".to_string(),
    }))
  }

  async fn list_rule_versions(
    &self,
    _request: Request<ListRuleVersionsRequest>,
  ) -> Result<Response<ListRuleVersionsResponse>, Status> {
    let versions = ops::list_rule_versions(&self.state)
      .await
      .map_err(|e| Status::internal(e.to_string()))?
      .into_iter()
      .map(|entry| RuleVersion {
        id: entry.id,
        version: entry.version,
        created_at: entry.created_at.to_rfc3339(),
        active: entry.active,
      })
      .collect();

    Ok(Response::new(ListRuleVersionsResponse { versions }))
  }
}
