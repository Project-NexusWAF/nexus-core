//! Metric definitions for Nexus observability.
//!
//! All metrics are lazily initialized and registered with the global Prometheus registry.

use once_cell::sync::Lazy;
use prometheus::{
    register_counter_vec, register_gauge_vec, register_histogram_vec, register_counter,
    register_histogram, register_gauge, CounterVec, GaugeVec, HistogramVec, Counter, Histogram,
    Gauge,
};

/// Total requests by HTTP method and response status.
pub static NEXUS_REQUESTS_TOTAL: Lazy<CounterVec> = Lazy::new(|| {
    register_counter_vec!(
        "nexus_requests_total",
        "Total number of requests by HTTP method and response status",
        &["method", "status"]
    )
    .expect("failed to register nexus_requests_total")
});

/// End-to-end request duration in milliseconds.
pub static NEXUS_REQUEST_DURATION_MS: Lazy<Histogram> = Lazy::new(|| {
    register_histogram!(
        "nexus_request_duration_ms",
        "End-to-end request latency in milliseconds",
        vec![1.0, 5.0, 10.0, 25.0, 50.0, 100.0, 250.0, 500.0, 1000.0, 5000.0]
    )
    .expect("failed to register nexus_request_duration_ms")
});

/// Total blocked requests by reason.
pub static NEXUS_BLOCKED_REQUESTS_TOTAL: Lazy<CounterVec> = Lazy::new(|| {
    register_counter_vec!(
        "nexus_blocked_requests_total",
        "Total number of blocked requests by reason",
        &["reason"]
    )
    .expect("failed to register nexus_blocked_requests_total")
});

/// Per-layer processing time in microseconds.
pub static NEXUS_LAYER_DURATION_US: Lazy<HistogramVec> = Lazy::new(|| {
    register_histogram_vec!(
        "nexus_layer_duration_us",
        "Per-layer processing time in microseconds",
        &["layer"],
        vec![10.0, 50.0, 100.0, 250.0, 500.0, 1000.0, 2500.0, 5000.0, 10000.0, 50000.0]
    )
    .expect("failed to register nexus_layer_duration_us")
});

/// ML gRPC call duration in milliseconds.
pub static NEXUS_ML_INFERENCE_DURATION_MS: Lazy<Histogram> = Lazy::new(|| {
    register_histogram!(
        "nexus_ml_inference_duration_ms",
        "ML inference call duration in milliseconds",
        vec![1.0, 2.0, 5.0, 10.0, 25.0, 50.0, 100.0, 250.0]
    )
    .expect("failed to register nexus_ml_inference_duration_ms")
});

/// Total requests flagged by ML.
pub static NEXUS_ML_DETECTIONS_TOTAL: Lazy<Counter> = Lazy::new(|| {
    register_counter!(
        "nexus_ml_detections_total",
        "Total number of requests flagged by ML"
    )
    .expect("failed to register nexus_ml_detections_total")
});

/// Current open client connections.
pub static NEXUS_ACTIVE_CONNECTIONS: Lazy<Gauge> = Lazy::new(|| {
    register_gauge!(
        "nexus_active_connections",
        "Current number of open client connections"
    )
    .expect("failed to register nexus_active_connections")
});

/// Upstream health status (1.0 = healthy, 0.0 = unhealthy).
pub static NEXUS_UPSTREAM_HEALTH: Lazy<GaugeVec> = Lazy::new(|| {
    register_gauge_vec!(
        "nexus_upstream_health",
        "Upstream health status (1.0 = healthy, 0.0 = unhealthy)",
        &["upstream"]
    )
    .expect("failed to register nexus_upstream_health")
});

/// Total rate-limited requests per IP.
pub static NEXUS_RATE_LIMITED_TOTAL: Lazy<CounterVec> = Lazy::new(|| {
    register_counter_vec!(
        "nexus_rate_limited_total",
        "Total number of rate-limited requests per client IP",
        &["client_ip"]
    )
    .expect("failed to register nexus_rate_limited_total")
});

/// Rule engine matches per rule and action.
pub static NEXUS_RULE_MATCHES_TOTAL: Lazy<CounterVec> = Lazy::new(|| {
    register_counter_vec!(
        "nexus_rule_matches_total",
        "Total number of rule engine matches per rule and action",
        &["rule_id", "action"]
    )
    .expect("failed to register nexus_rule_matches_total")
});

/// Force registration of all metrics at startup.
pub fn register_all() {
    Lazy::force(&NEXUS_REQUESTS_TOTAL);
    Lazy::force(&NEXUS_REQUEST_DURATION_MS);
    Lazy::force(&NEXUS_BLOCKED_REQUESTS_TOTAL);
    Lazy::force(&NEXUS_LAYER_DURATION_US);
    Lazy::force(&NEXUS_ML_INFERENCE_DURATION_MS);
    Lazy::force(&NEXUS_ML_DETECTIONS_TOTAL);
    Lazy::force(&NEXUS_ACTIVE_CONNECTIONS);
    Lazy::force(&NEXUS_UPSTREAM_HEALTH);
    Lazy::force(&NEXUS_RATE_LIMITED_TOTAL);
    Lazy::force(&NEXUS_RULE_MATCHES_TOTAL);
}
