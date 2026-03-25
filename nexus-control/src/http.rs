use std::sync::Arc;

use axum::{
  extract::{Path, Query, State},
  http::StatusCode,
  middleware,
  response::IntoResponse,
  routing::get,
  Json, Router,
};
use uuid::Uuid;

use crate::ops::{self, LogsQuery};
use crate::stats::UpdateRulesBody;
use crate::ControlAppState;

pub fn rest_router(state: Arc<ControlAppState>) -> Router {
  let token = Arc::new(state.admin_token.clone());

  let protected = Router::new()
    .route("/api/stats", get(stats_handler))
    .route("/api/logs", get(logs_handler))
    .route("/api/logs/:id", get(log_detail_handler))
    .route(
      "/api/rules",
      get(get_rules_handler).post(update_rules_handler),
    )
    .route("/api/rules/versions", get(rule_versions_handler))
    .route("/api/config", get(config_handler))
    .route("/api/config/logs", get(config_logs_handler))
    .layer(middleware::from_fn_with_state(
      token,
      crate::auth::require_auth,
    ));

  let public = Router::new().route("/api/health", get(health_handler));

  Router::new()
    .merge(protected)
    .merge(public)
    .with_state(state)
}

async fn health_handler(State(state): State<Arc<ControlAppState>>) -> impl IntoResponse {
  (StatusCode::OK, Json(ops::health_snapshot(&state)))
}

async fn stats_handler(State(state): State<Arc<ControlAppState>>) -> impl IntoResponse {
  (StatusCode::OK, Json(ops::stats_snapshot(&state)))
}

async fn logs_handler(
  State(state): State<Arc<ControlAppState>>,
  Query(query): Query<LogsQuery>,
) -> impl IntoResponse {
  match ops::list_logs(&state, query).await {
    Ok(result) => (
      StatusCode::OK,
      Json(serde_json::to_value(result).unwrap_or_default()),
    ),
    Err(error) => internal_error(error),
  }
}

async fn log_detail_handler(
  State(state): State<Arc<ControlAppState>>,
  Path(id): Path<Uuid>,
) -> impl IntoResponse {
  match ops::get_log_detail(&state, id).await {
    Ok(Some(result)) => (
      StatusCode::OK,
      Json(serde_json::to_value(result).unwrap_or_default()),
    ),
    Ok(None) => (
      StatusCode::NOT_FOUND,
      Json(serde_json::json!({ "error": "log not found" })),
    ),
    Err(error) => internal_error(error),
  }
}

async fn get_rules_handler(State(state): State<Arc<ControlAppState>>) -> impl IntoResponse {
  match ops::get_rules(&state).await {
    Ok(result) => (
      StatusCode::OK,
      Json(serde_json::to_value(result).unwrap_or_default()),
    ),
    Err(error) => internal_error(error),
  }
}

async fn update_rules_handler(
  State(state): State<Arc<ControlAppState>>,
  Json(body): Json<UpdateRulesBody>,
) -> impl IntoResponse {
  match ops::update_rules(&state, &body.version, &body.content).await {
    Ok(config_version) => (
      StatusCode::CREATED,
      Json(serde_json::json!({
        "updated": true,
        "config_version": config_version
      })),
    ),
    Err(error) => (
      StatusCode::BAD_REQUEST,
      Json(serde_json::json!({ "error": error.to_string() })),
    ),
  }
}

async fn rule_versions_handler(State(state): State<Arc<ControlAppState>>) -> impl IntoResponse {
  match ops::list_rule_versions(&state).await {
    Ok(result) => (
      StatusCode::OK,
      Json(serde_json::to_value(result).unwrap_or_default()),
    ),
    Err(error) => internal_error(error),
  }
}

async fn config_handler(State(state): State<Arc<ControlAppState>>) -> impl IntoResponse {
  (StatusCode::OK, Json(ops::config_snapshot(&state)))
}

async fn config_logs_handler(State(state): State<Arc<ControlAppState>>) -> impl IntoResponse {
  (StatusCode::OK, Json(ops::list_config_logs(&state)))
}

fn internal_error(error: anyhow::Error) -> (StatusCode, Json<serde_json::Value>) {
  tracing::error!(error = %error, "control API request failed");
  (
    StatusCode::INTERNAL_SERVER_ERROR,
    Json(serde_json::json!({ "error": "internal server error" })),
  )
}
