//! Public recording API for Nexus metrics.
//!
//! This module provides clean, type-safe functions for recording metrics
//! without exposing raw Prometheus types to other crates.

use crate::metrics::*;
use std::time::Duration;

/// Record a request with its HTTP method and response status.
///
/// # Example
/// ```
/// nexus_metrics::record_request("GET", 200);
/// nexus_metrics::record_request("POST", 403);
/// ```
pub fn record_request(method: &str, status_code: u16) {
    NEXUS_REQUESTS_TOTAL
        .with_label_values(&[method, &status_code.to_string()])
        .inc();
}

/// Record the end-to-end duration of a request.
///
/// Duration is automatically converted to milliseconds.
///
/// # Example
/// ```
/// use std::time::Duration;
/// nexus_metrics::record_request_duration(Duration::from_millis(42));
/// ```
pub fn record_request_duration(duration: Duration) {
    let millis = duration.as_secs_f64() * 1000.0;
    NEXUS_REQUEST_DURATION_MS.observe(millis);
}

/// Record a blocked request with the reason for blocking.
///
/// Reasons can be: "sqli", "xss", "rule:R001", "rate_limit", etc.
///
/// # Example
/// ```
/// nexus_metrics::record_blocked("sqli");
/// nexus_metrics::record_blocked("rule:R001");
/// ```
pub fn record_blocked(reason: &str) {
    NEXUS_BLOCKED_REQUESTS_TOTAL
        .with_label_values(&[reason])
        .inc();
}

/// Record the processing time for a specific layer.
///
/// Layer names: "rate", "lexical", "grammar", "rules", "ml"
/// Duration is automatically converted to microseconds.
///
/// # Example
/// ```
/// use std::time::Duration;
/// nexus_metrics::record_layer_duration("lexical", Duration::from_micros(150));
/// ```
pub fn record_layer_duration(layer: &str, duration: Duration) {
    let micros = duration.as_secs_f64() * 1_000_000.0;
    NEXUS_LAYER_DURATION_US
        .with_label_values(&[layer])
        .observe(micros);
}

/// Record an ML inference call.
///
/// Duration is automatically converted to milliseconds.
/// If `detected` is true, also increments the ML detections counter.
///
/// # Example
/// ```
/// use std::time::Duration;
/// nexus_metrics::record_ml_inference(Duration::from_millis(8), true);
/// nexus_metrics::record_ml_inference(Duration::from_millis(5), false);
/// ```
pub fn record_ml_inference(duration: Duration, detected: bool) {
    let millis = duration.as_secs_f64() * 1000.0;
    NEXUS_ML_INFERENCE_DURATION_MS.observe(millis);
    
    if detected {
        NEXUS_ML_DETECTIONS_TOTAL.inc();
    }
}

/// Set the current number of active client connections.
///
/// Use i64 to allow both incrementing and decrementing.
///
/// # Example
/// ```
/// nexus_metrics::set_active_connections(42);
/// nexus_metrics::set_active_connections(0);
/// ```
pub fn set_active_connections(count: i64) {
    NEXUS_ACTIVE_CONNECTIONS.set(count as f64);
}

/// Set the health status of an upstream server.
///
/// `healthy = true` sets the gauge to 1.0, `false` sets it to 0.0.
///
/// # Example
/// ```
/// nexus_metrics::set_upstream_health("192.168.1.10:8080", true);
/// nexus_metrics::set_upstream_health("192.168.1.11:8080", false);
/// ```
pub fn set_upstream_health(addr: &str, healthy: bool) {
    let value = if healthy { 1.0 } else { 0.0 };
    NEXUS_UPSTREAM_HEALTH
        .with_label_values(&[addr])
        .set(value);
}

/// Record a rate-limited request from a specific client IP.
///
/// # Example
/// ```
/// nexus_metrics::record_rate_limited("203.0.113.42");
/// ```
pub fn record_rate_limited(client_ip: &str) {
    NEXUS_RATE_LIMITED_TOTAL
        .with_label_values(&[client_ip])
        .inc();
}

/// Record a rule engine match.
///
/// # Example
/// ```
/// nexus_metrics::record_rule_match("R001", "block");
/// nexus_metrics::record_rule_match("R002", "log");
/// ```
pub fn record_rule_match(rule_id: &str, action: &str) {
    NEXUS_RULE_MATCHES_TOTAL
        .with_label_values(&[rule_id, action])
        .inc();
}
