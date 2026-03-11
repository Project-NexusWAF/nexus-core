//! Nexus Metrics — Prometheus instrumentation for the Nexus WAF.
//!
//! This crate provides comprehensive observability for the Nexus system:
//! - Request rates and latency percentiles
//! - Block rates by attack type
//! - Per-layer processing time
//! - ML inference metrics
//! - Upstream health status
//!
//! # Usage
//!
//! Initialize metrics at startup:
//! ```
//! nexus_metrics::init();
//! ```
//!
//! Record events throughout your application:
//! ```
//! use std::time::Duration;
//!
//! // Record a successful request
//! nexus_metrics::record_request("GET", 200);
//! nexus_metrics::record_request_duration(Duration::from_millis(42));
//!
//! // Record a blocked attack
//! nexus_metrics::record_blocked("sqli");
//!
//! // Record layer timing
//! nexus_metrics::record_layer_duration("lexical", Duration::from_micros(150));
//!
//! // Record ML inference
//! nexus_metrics::record_ml_inference(Duration::from_millis(8), true);
//!
//! // Update gauges
//! nexus_metrics::set_active_connections(42);
//! nexus_metrics::set_upstream_health("192.168.1.10:8080", true);
//!
//! // Record rate limiting and rule matches
//! nexus_metrics::record_rate_limited("203.0.113.42");
//! nexus_metrics::record_rule_match("R001", "block");
//! ```
//!
//! Export metrics for Prometheus scraping:
//! ```
//! let output = nexus_metrics::gather_metrics();
//! // Serve this at GET /metrics
//! ```

mod exporter;
mod metrics;
mod recorder;

// Re-export public API
pub use exporter::gather_metrics;
pub use recorder::{
    record_blocked, record_layer_duration, record_ml_inference, record_rate_limited,
    record_request, record_request_duration, record_rule_match, set_active_connections,
    set_upstream_health,
};

/// Initialize the metrics subsystem.
///
/// This forces registration of all metrics with the global Prometheus registry,
/// ensuring they appear in the first scrape even before any requests arrive.
///
/// Safe to call multiple times; subsequent calls are no-ops.
///
/// # Example
/// ```
/// nexus_metrics::init();
/// ```
pub fn init() {
    metrics::register_all();
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_init_does_not_panic() {
        init();
        init(); // Should be safe to call multiple times
    }

    #[test]
    fn test_record_request() {
        record_request("GET", 200);
        record_request("POST", 403);
        // Verify metrics contain expected labels
        let output = gather_metrics();
        assert!(output.contains("nexus_requests_total"));
    }

    #[test]
    fn test_record_request_duration() {
        record_request_duration(Duration::from_millis(42));
        record_request_duration(Duration::from_secs(1));
        let output = gather_metrics();
        assert!(output.contains("nexus_request_duration_ms"));
    }

    #[test]
    fn test_record_blocked() {
        record_blocked("sqli");
        record_blocked("xss");
        record_blocked("rule:R001");
        let output = gather_metrics();
        assert!(output.contains("nexus_blocked_requests_total"));
    }

    #[test]
    fn test_record_layer_duration() {
        record_layer_duration("rate", Duration::from_micros(100));
        record_layer_duration("lexical", Duration::from_micros(150));
        record_layer_duration("grammar", Duration::from_millis(1));
        record_layer_duration("rules", Duration::from_micros(200));
        record_layer_duration("ml", Duration::from_millis(10));
        let output = gather_metrics();
        assert!(output.contains("nexus_layer_duration_us"));
    }

    #[test]
    fn test_record_ml_inference_with_detection() {
        let before = gather_metrics();
        let count_before = before
            .lines()
            .find(|line| line.starts_with("nexus_ml_detections_total"))
            .and_then(|line| line.split_whitespace().nth(1))
            .and_then(|s| s.parse::<f64>().ok())
            .unwrap_or(0.0);

        record_ml_inference(Duration::from_millis(8), true);

        let after = gather_metrics();
        let count_after = after
            .lines()
            .find(|line| line.starts_with("nexus_ml_detections_total"))
            .and_then(|line| line.split_whitespace().nth(1))
            .and_then(|s| s.parse::<f64>().ok())
            .unwrap_or(0.0);

        assert!(count_after > count_before, "ML detection counter should increase");
    }

    #[test]
    fn test_record_ml_inference_without_detection() {
        init(); // Ensure metric exists
        
        let before = gather_metrics();
        let count_before = before
            .lines()
            .find(|line| line.starts_with("nexus_ml_detections_total"))
            .and_then(|line| line.split_whitespace().nth(1))
            .and_then(|s| s.parse::<f64>().ok())
            .unwrap_or(0.0);

        record_ml_inference(Duration::from_millis(5), false);

        let after = gather_metrics();
        let count_after = after
            .lines()
            .find(|line| line.starts_with("nexus_ml_detections_total"))
            .and_then(|line| line.split_whitespace().nth(1))
            .and_then(|s| s.parse::<f64>().ok())
            .unwrap_or(0.0);

        assert_eq!(count_after, count_before, "ML detection counter should not increase when detected=false");
    }

    #[test]
    fn test_set_active_connections() {
        set_active_connections(42);
        set_active_connections(0);
        set_active_connections(-5); // Should work with negative values
        let output = gather_metrics();
        assert!(output.contains("nexus_active_connections"));
    }

    #[test]
    fn test_set_upstream_health() {
        set_upstream_health("192.168.1.10:8080", true);
        let output_healthy = gather_metrics();
        assert!(output_healthy.contains("nexus_upstream_health"));

        set_upstream_health("192.168.1.11:8080", false);
        let output_unhealthy = gather_metrics();
        
        // Verify the gauge values are present
        assert!(output_unhealthy.contains("upstream=\"192.168.1.10:8080\""));
        assert!(output_unhealthy.contains("upstream=\"192.168.1.11:8080\""));
    }

    #[test]
    fn test_record_rate_limited() {
        record_rate_limited("203.0.113.42");
        record_rate_limited("198.51.100.1");
        let output = gather_metrics();
        assert!(output.contains("nexus_rate_limited_total"));
    }

    #[test]
    fn test_record_rule_match() {
        record_rule_match("R001", "block");
        record_rule_match("R002", "log");
        record_rule_match("R003", "allow");
        let output = gather_metrics();
        assert!(output.contains("nexus_rule_matches_total"));
    }

    #[test]
    fn test_gather_metrics_returns_valid_output() {
        init();
        
        // Record some metrics
        record_request("GET", 200);
        record_blocked("sqli");
        set_active_connections(5);
        
        let output = gather_metrics();
        
        // Should contain metric names
        assert!(output.contains("nexus_requests_total"));
        assert!(output.contains("nexus_blocked_requests_total"));
        assert!(output.contains("nexus_active_connections"));
        
        // Should be valid Prometheus format (starts with # HELP or metric names)
        assert!(!output.is_empty());
        assert!(output.lines().any(|line| line.starts_with("# HELP") || line.starts_with("nexus_")));
    }

    #[test]
    fn test_all_metrics_present_after_init() {
        init();
        
        // Record at least one value for each metric so they appear in output
        record_request("GET", 200);
        record_request_duration(Duration::from_millis(10));
        record_blocked("test");
        record_layer_duration("test", Duration::from_micros(100));
        record_ml_inference(Duration::from_millis(5), false);
        set_active_connections(0);
        set_upstream_health("test", true);
        record_rate_limited("test");
        record_rule_match("test", "test");
        
        let output = gather_metrics();
        
        // All metrics should be registered and appear in output
        assert!(output.contains("nexus_requests_total"), "Missing nexus_requests_total");
        assert!(output.contains("nexus_request_duration_ms"), "Missing nexus_request_duration_ms");
        assert!(output.contains("nexus_blocked_requests_total"), "Missing nexus_blocked_requests_total");
        assert!(output.contains("nexus_layer_duration_us"), "Missing nexus_layer_duration_us");
        assert!(output.contains("nexus_ml_inference_duration_ms"), "Missing nexus_ml_inference_duration_ms");
        assert!(output.contains("nexus_ml_detections_total"), "Missing nexus_ml_detections_total");
        assert!(output.contains("nexus_active_connections"), "Missing nexus_active_connections");
        assert!(output.contains("nexus_upstream_health"), "Missing nexus_upstream_health");
        assert!(output.contains("nexus_rate_limited_total"), "Missing nexus_rate_limited_total");
        assert!(output.contains("nexus_rule_matches_total"), "Missing nexus_rule_matches_total");
    }
}
