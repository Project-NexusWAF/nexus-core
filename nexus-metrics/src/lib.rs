use axum::body::Body;
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::Response;
use axum::routing::get;
use axum::Router;
use once_cell::sync::Lazy;
use prometheus::{
  Encoder, HistogramOpts, HistogramVec, IntCounter, IntCounterVec, Opts, Registry, TextEncoder,
};

struct Metrics {
  registry: Registry,
  requests_total: IntCounterVec,
  request_duration_ms: HistogramVec,
  blocks_total: IntCounterVec,
  layer_duration_us: HistogramVec,
  rate_limit_total: IntCounter,
  ml_duration_ms: HistogramVec,
  rule_match_total: IntCounterVec,
  upstream_requests_total: IntCounterVec,
  upstream_latency_ms: HistogramVec,
  lb_selected_total: IntCounterVec,
}

static METRICS: Lazy<Metrics> = Lazy::new(|| {
  let registry = Registry::new();

  let requests_total = IntCounterVec::new(
    Opts::new(
      "nexus_requests_total",
      "Total requests observed by method and decision",
    ),
    &["method", "decision"],
  )
  .expect("requests_total metrics");

  let request_duration_ms = HistogramVec::new(
    HistogramOpts::new(
      "nexus_request_duration_ms",
      "Request latency distribution (ms)",
    ),
    &["method", "decision"],
  )
  .expect("request_duration_ms metrics");

  let blocks_total = IntCounterVec::new(
    Opts::new(
      "nexus_blocks_total",
      "Total blocked requests by layer and code",
    ),
    &["layer", "code"],
  )
  .expect("blocks_total metrics");

  let layer_duration_us = HistogramVec::new(
    HistogramOpts::new(
      "nexus_layer_duration_us",
      "Per-layer execution time (microseconds)",
    )
    .buckets(vec![
      10.0, 25.0, 50.0, 100.0, 250.0, 500.0, 1_000.0, 2_500.0, 5_000.0, 10_000.0, 25_000.0,
      50_000.0, 100_000.0, 250_000.0, 500_000.0, 1_000_000.0,
    ]),
    &["layer"],
  )
  .expect("layer_duration_us metrics");

  let rate_limit_total = IntCounter::new(
    "nexus_rate_limit_total",
    "Total requests that were rate-limited",
  )
  .expect("rate_limit_total metrics");

  let ml_duration_ms = HistogramVec::new(
    HistogramOpts::new(
      "nexus_ml_duration_ms",
      "ML inference latency distribution (ms)",
    ),
    &["label"],
  )
  .expect("ml_duration_ms metrics");

  let rule_match_total = IntCounterVec::new(
    Opts::new(
      "nexus_rule_match_total",
      "Total rule matches by rule id and action",
    ),
    &["rule_id", "action"],
  )
  .expect("rule_match_total metrics");

  let upstream_requests_total = IntCounterVec::new(
    Opts::new(
      "nexus_upstream_requests_total",
      "Upstream requests by addr and result",
    ),
    &["addr", "result"],
  )
  .expect("upstream_requests_total metrics");

  let upstream_latency_ms = HistogramVec::new(
    HistogramOpts::new(
      "nexus_upstream_latency_ms",
      "Upstream request latency distribution (ms)",
    ),
    &["addr", "result"],
  )
  .expect("upstream_latency_ms metrics");

  let lb_selected_total = IntCounterVec::new(
    Opts::new(
      "nexus_lb_selected_total",
      "Load balancer selections by addr and algorithm",
    ),
    &["addr", "algorithm"],
  )
  .expect("lb_selected_total metrics");

  registry
    .register(Box::new(requests_total.clone()))
    .expect("register requests_total");
  registry
    .register(Box::new(request_duration_ms.clone()))
    .expect("register request_duration_ms");
  registry
    .register(Box::new(blocks_total.clone()))
    .expect("register blocks_total");
  registry
    .register(Box::new(layer_duration_us.clone()))
    .expect("register layer_duration_us");
  registry
    .register(Box::new(rate_limit_total.clone()))
    .expect("register rate_limit_total");
  registry
    .register(Box::new(ml_duration_ms.clone()))
    .expect("register ml_duration_ms");
  registry
    .register(Box::new(rule_match_total.clone()))
    .expect("register rule_match_total");
  registry
    .register(Box::new(upstream_requests_total.clone()))
    .expect("register upstream_requests_total");
  registry
    .register(Box::new(upstream_latency_ms.clone()))
    .expect("register upstream_latency_ms");
  registry
    .register(Box::new(lb_selected_total.clone()))
    .expect("register lb_selected_total");

  Metrics {
    registry,
    requests_total,
    request_duration_ms,
    blocks_total,
    layer_duration_us,
    rate_limit_total,
    ml_duration_ms,
    rule_match_total,
    upstream_requests_total,
    upstream_latency_ms,
    lb_selected_total,
  }
});

pub struct MetricsRegistry;

impl MetricsRegistry {
  pub fn record_request(method: &str, decision: &str, duration_ms: f64) {
    METRICS
      .requests_total
      .with_label_values(&[method, decision])
      .inc();
    METRICS
      .request_duration_ms
      .with_label_values(&[method, decision])
      .observe(duration_ms);
  }

  pub fn record_block(layer: &str, code: &str) {
    METRICS
      .blocks_total
      .with_label_values(&[layer, code])
      .inc();
  }

  pub fn record_layer(layer: &str, duration_us: f64) {
    METRICS
      .layer_duration_us
      .with_label_values(&[layer])
      .observe(duration_us);
  }

  pub fn record_ml(duration_ms: f64, label: Option<&str>) {
    METRICS
      .ml_duration_ms
      .with_label_values(&[label.unwrap_or("unknown")])
      .observe(duration_ms);
  }

  pub fn record_rate_limit() {
    METRICS.rate_limit_total.inc();
  }

  pub fn record_rule_match(rule_id: &str, action: &str) {
    METRICS
      .rule_match_total
      .with_label_values(&[rule_id, action])
      .inc();
  }

  pub fn record_upstream(addr: &str, result: &str, duration_ms: f64) {
    METRICS
      .upstream_requests_total
      .with_label_values(&[addr, result])
      .inc();
    METRICS
      .upstream_latency_ms
      .with_label_values(&[addr, result])
      .observe(duration_ms);
  }

  pub fn record_lb_selection(addr: &str, algorithm: &str) {
    METRICS
      .lb_selected_total
      .with_label_values(&[addr, algorithm])
      .inc();
  }
}

pub async fn serve_metrics(addr: String) -> anyhow::Result<()> {
  let router = Router::new().route("/metrics", get(metrics_handler));
  let listener = tokio::net::TcpListener::bind(&addr).await?;
  tracing::info!(addr = %addr, "metrics endpoint listening");
  axum::serve(listener, router).await?;
  Ok(())
}

async fn metrics_handler() -> Response<Body> {
  let encoder = TextEncoder::new();
  let metric_families = METRICS.registry.gather();
  let mut buffer = Vec::new();
  let status = match encoder.encode(&metric_families, &mut buffer) {
    Ok(_) => StatusCode::OK,
    Err(error) => {
      tracing::error!(error = %error, "failed to encode metrics");
      buffer = b"# metrics encode error\n".to_vec();
      StatusCode::INTERNAL_SERVER_ERROR
    }
  };

  let mut response = Response::new(Body::from(buffer));
  *response.status_mut() = status;
  response.headers_mut().insert(
    header::CONTENT_TYPE,
    HeaderValue::from_str(encoder.format_type()).unwrap_or_else(|_| {
      HeaderValue::from_static("text/plain; version=0.0.4; charset=utf-8")
    }),
  );
  response
}
