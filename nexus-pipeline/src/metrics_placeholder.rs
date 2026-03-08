/// Temporary no-op metrics facade.
///
/// TODO: replace with real `nexus-metrics` integration once that crate lands.
pub struct MetricsRegistry;

impl MetricsRegistry {
  pub fn record_layer(_layer: &str, _duration_us: f64) {}

  pub fn record_rate_limit() {}

  pub fn record_block(_layer: &str, _code: &str) {}

  pub fn record_request(_method: &str, _decision: &str, _latency_ms: f64) {}
}
