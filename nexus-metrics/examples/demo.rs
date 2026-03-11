//! Demo program to test nexus-metrics functionality.
//!
//! Run with: cargo run -p nexus-metrics --example demo

use std::time::Duration;

fn main() {
    println!("🚀 Nexus Metrics Demo\n");
    
    // Initialize metrics
    println!("Initializing metrics...");
    nexus_metrics::init();
    println!("✓ Metrics initialized\n");
    
    // Simulate some requests
    println!("Simulating HTTP requests...");
    nexus_metrics::record_request("GET", 200);
    nexus_metrics::record_request("GET", 200);
    nexus_metrics::record_request("POST", 200);
    nexus_metrics::record_request("GET", 403);
    nexus_metrics::record_request_duration(Duration::from_millis(42));
    nexus_metrics::record_request_duration(Duration::from_millis(8));
    nexus_metrics::record_request_duration(Duration::from_millis(156));
    println!("✓ Recorded 4 requests\n");
    
    // Simulate attacks being blocked
    println!("Simulating blocked attacks...");
    nexus_metrics::record_blocked("sqli");
    nexus_metrics::record_blocked("sqli");
    nexus_metrics::record_blocked("xss");
    nexus_metrics::record_blocked("rule:R001");
    println!("✓ Recorded 4 blocks\n");
    
    // Simulate layer processing
    println!("Simulating layer processing...");
    nexus_metrics::record_layer_duration("rate", Duration::from_micros(100));
    nexus_metrics::record_layer_duration("lexical", Duration::from_micros(150));
    nexus_metrics::record_layer_duration("grammar", Duration::from_micros(800));
    nexus_metrics::record_layer_duration("rules", Duration::from_micros(200));
    nexus_metrics::record_layer_duration("ml", Duration::from_millis(12));
    println!("✓ Recorded 5 layer timings\n");
    
    // Simulate ML inference
    println!("Simulating ML inference...");
    nexus_metrics::record_ml_inference(Duration::from_millis(8), true);  // detected
    nexus_metrics::record_ml_inference(Duration::from_millis(5), false); // clean
    nexus_metrics::record_ml_inference(Duration::from_millis(12), true); // detected
    println!("✓ Recorded 3 ML inferences (2 detections)\n");
    
    // Update gauges
    println!("Updating gauges...");
    nexus_metrics::set_active_connections(42);
    nexus_metrics::set_upstream_health("192.168.1.10:8080", true);
    nexus_metrics::set_upstream_health("192.168.1.11:8080", false);
    nexus_metrics::set_upstream_health("192.168.1.12:8080", true);
    println!("✓ Updated connection count and upstream health\n");
    
    // Simulate rate limiting
    println!("Simulating rate limiting...");
    nexus_metrics::record_rate_limited("203.0.113.42");
    nexus_metrics::record_rate_limited("203.0.113.42");
    nexus_metrics::record_rate_limited("198.51.100.1");
    println!("✓ Recorded 3 rate limits\n");
    
    // Simulate rule matches
    println!("Simulating rule matches...");
    nexus_metrics::record_rule_match("R001", "block");
    nexus_metrics::record_rule_match("R002", "log");
    nexus_metrics::record_rule_match("R003", "allow");
    nexus_metrics::record_rule_match("R001", "block");
    println!("✓ Recorded 4 rule matches\n");
    
    // Gather and display metrics
    println!("{}", "=".repeat(80));
    println!("📊 PROMETHEUS METRICS OUTPUT");
    println!("{}", "=".repeat(80));
    println!();
    
    let metrics = nexus_metrics::gather_metrics();
    println!("{}", metrics);
    
    println!("{}", "=".repeat(80));
    println!("\n✅ Demo complete! All metrics recorded successfully.");
    println!("\nKey observations:");
    println!("  • nexus_requests_total: Should show GET=3, POST=1");
    println!("  • nexus_blocked_requests_total: Should show sqli=2, xss=1, rule:R001=1");
    println!("  • nexus_ml_detections_total: Should be 2");
    println!("  • nexus_active_connections: Should be 42");
    println!("  • nexus_upstream_health: Should show 3 upstreams (2 healthy, 1 unhealthy)");
    println!("  • nexus_rate_limited_total: Should show 2 IPs");
    println!("  • nexus_rule_matches_total: Should show 4 matches across 3 rules");
}
