//! Prometheus text format exporter.
//!
//! Provides the `/metrics` endpoint output in Prometheus exposition format.

use prometheus::{Encoder, TextEncoder};

/// Gather all registered metrics and encode them in Prometheus text format.
///
/// This is the function that powers the `/metrics` HTTP endpoint.
///
/// # Example
/// ```
/// let metrics_output = nexus_metrics::gather_metrics();
/// println!("{}", metrics_output);
/// ```
pub fn gather_metrics() -> String {
    let encoder = TextEncoder::new();
    let metric_families = prometheus::gather();
    
    let mut buffer = Vec::new();
    if let Err(e) = encoder.encode(&metric_families, &mut buffer) {
        tracing::error!("failed to encode metrics: {}", e);
        return String::from("# encoding error\n");
    }
    
    String::from_utf8(buffer).unwrap_or_else(|e| {
        tracing::error!("failed to convert metrics to UTF-8: {}", e);
        String::from("# UTF-8 conversion error\n")
    })
}
