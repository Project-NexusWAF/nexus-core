use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::get;
use axum::Router;
use std::sync::Arc;

#[derive(Clone, Default)]
struct MetricsState;

pub async fn serve_metrics(addr: String) -> anyhow::Result<()> {
  let state = Arc::new(MetricsState::default());
  let app = Router::new()
    .route("/metrics", get(metrics_handler))
    .with_state(state);

  let listener = tokio::net::TcpListener::bind(&addr).await?;
  tracing::warn!(
    addr = %addr,
    "metrics placeholder active; real metrics service is not integrated yet"
  );
  axum::serve(listener, app).await?;
  Ok(())
}

async fn metrics_handler(State(_state): State<Arc<MetricsState>>) -> (StatusCode, &'static str) {
  (
    StatusCode::NOT_IMPLEMENTED,
    "# nexus-metrics placeholder\n# real Prometheus registry not integrated yet\n",
  )
}
