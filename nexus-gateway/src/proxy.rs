use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::body::{to_bytes, Body};
use axum::extract::{ConnectInfo, State};
use axum::http::header::{self, HeaderName, HeaderValue};
use axum::http::{Request, Response, StatusCode, Uri};
use bytes::Bytes;
use http_body_util::Full;
use nexus_common::{Decision, RequestContext};
use nexus_config::schema::LbAlgorithm;
use nexus_metrics::MetricsRegistry;

use crate::state::AppState;

pub async fn proxy_handler(
  State(state): State<Arc<AppState>>,
  ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
  request: Request<Body>,
) -> Response<Body> {
  let cfg = state.active_config();
  let max_body_bytes = cfg.gateway.max_body_bytes;
  let request_timeout = Duration::from_millis(cfg.gateway.request_timeout_ms);
  let trust_xff = cfg.gateway.trust_x_forwarded_for;
  let lb_algorithm = cfg.lb.algorithm.clone();
  drop(cfg);

  let client_ip = extract_client_ip(request.headers(), remote_addr, trust_xff);
  let (parts, body) = request.into_parts();

  let body_bytes = match to_bytes(body, max_body_bytes).await {
    Ok(bytes) => bytes,
    Err(error) => {
      tracing::warn!(error = %error, "request body exceeded configured size");
      return json_response(
        StatusCode::PAYLOAD_TOO_LARGE,
        serde_json::json!({ "error": "request body exceeds configured max_body_bytes" }),
      );
    }
  };

  let mut context = RequestContext::new(
    client_ip,
    parts.method.clone(),
    parts.uri.clone(),
    parts.version,
    parts.headers.clone(),
    body_bytes.clone(),
  );

  let pipeline = state.clone_pipeline();
  let result = pipeline.run(&mut context).await;
  log_layer_execution("proxy", &context, &result.timings);
  log_pipeline_outcome("proxy", &context, &result);

  state.control.requests_total.fetch_add(1, Ordering::Relaxed);
  if let Some(writer) = &state.policy_feedback {
    if let Some(event) = nexus_policy::PolicyFeedbackEvent::from_context(
      &context,
      &result.decision,
      result.decided_by.as_deref(),
      result.final_risk_score,
    ) {
      writer.record(event);
    }
  }
  if should_record_attack_event(&context, &result.decision) {
    if let Some(writer) = &state.control.log_writer {
      let event = nexus_store::BlockedEvent::from_context(
        &context,
        &result.decision,
        result.decided_by.as_deref(),
        result.final_risk_score,
      );
      state.slack_alerts.record_blocked(event.clone());
      writer.record(event);
    } else {
      let event = nexus_store::BlockedEvent::from_context(
        &context,
        &result.decision,
        result.decided_by.as_deref(),
        result.final_risk_score,
      );
      state.slack_alerts.record_blocked(event);
    }
  }

  if result.is_blocked() {
    if matches!(result.decision, Decision::RateLimit { .. }) {
      state
        .control
        .rate_limited_total
        .fetch_add(1, Ordering::Relaxed);
    } else {
      state.control.blocked_total.fetch_add(1, Ordering::Relaxed);
    }

    let decided_by = result.decided_by.clone();
    return block_response(result.decision, decided_by.as_deref());
  }

  let upstream = match state.select_upstream() {
    Ok(selection) => selection,
    Err(error) => {
      tracing::warn!(error = %error, "no healthy upstream available");
      return json_response(
        StatusCode::BAD_GATEWAY,
        serde_json::json!({ "error": "no healthy upstream available" }),
      );
    }
  };
  MetricsRegistry::record_lb_selection(&upstream.addr, lb_algorithm_label(&lb_algorithm));

  let upstream_uri = match build_upstream_uri(&upstream.addr, &parts.uri) {
    Ok(uri) => uri,
    Err(error) => {
      tracing::error!(error = %error, "failed to build upstream URI");
      return json_response(
        StatusCode::BAD_GATEWAY,
        serde_json::json!({ "error": "invalid upstream configuration" }),
      );
    }
  };

  let mut outbound = match Request::builder()
    .method(parts.method)
    .version(parts.version)
    .uri(upstream_uri)
    .body(Full::new(Bytes::from(body_bytes.to_vec())))
  {
    Ok(req) => req,
    Err(error) => {
      tracing::error!(error = %error, "failed to create upstream request");
      return json_response(
        StatusCode::INTERNAL_SERVER_ERROR,
        serde_json::json!({ "error": "failed to create upstream request" }),
      );
    }
  };

  copy_forward_headers(parts.headers, outbound.headers_mut(), &upstream.addr);

  let upstream_start = Instant::now();
  match tokio::time::timeout(request_timeout, state.http_client.request(outbound)).await {
    Ok(Ok(upstream_response)) => {
      upstream.record_success();
      MetricsRegistry::record_upstream(
        &upstream.addr,
        "success",
        upstream_start.elapsed().as_secs_f64() * 1_000.0,
      );
      map_upstream_response(upstream_response)
    }
    Ok(Err(error)) => {
      upstream.record_failure();
      MetricsRegistry::record_upstream(
        &upstream.addr,
        "error",
        upstream_start.elapsed().as_secs_f64() * 1_000.0,
      );
      tracing::warn!(error = %error, "upstream request failed");
      json_response(
        StatusCode::BAD_GATEWAY,
        serde_json::json!({ "error": "upstream request failed" }),
      )
    }
    Err(_) => {
      upstream.record_failure();
      MetricsRegistry::record_upstream(
        &upstream.addr,
        "timeout",
        upstream_start.elapsed().as_secs_f64() * 1_000.0,
      );
      json_response(
        StatusCode::GATEWAY_TIMEOUT,
        serde_json::json!({ "error": "upstream timeout" }),
      )
    }
  }
}

fn block_response(decision: Decision, decided_by: Option<&str>) -> Response<Body> {
  let blocked_by = decided_by.unwrap_or("unknown");
  match decision {
    Decision::RateLimit {
      retry_after_seconds,
    } => {
      let mut response = json_response(
        StatusCode::TOO_MANY_REQUESTS,
        serde_json::json!({
          "message": format!("Request rate-limited by {blocked_by}"),
          "retry_after_seconds": retry_after_seconds
        }),
      );
      if let Ok(value) = HeaderValue::from_str(&retry_after_seconds.to_string()) {
        response.headers_mut().insert(header::RETRY_AFTER, value);
      }
      response
    }
    Decision::Block { reason, .. } => json_response(
      StatusCode::FORBIDDEN,
      serde_json::json!({ "message": format!("Request blocked by {blocked_by}: {reason}") }),
    ),
    _ => json_response(
      StatusCode::INTERNAL_SERVER_ERROR,
      serde_json::json!({ "message": "unexpected blocking decision" }),
    ),
  }
}

fn map_upstream_response(response: hyper::Response<hyper::body::Incoming>) -> Response<Body> {
  let (parts, body) = response.into_parts();
  let mut out = Response::builder()
    .status(parts.status)
    .version(parts.version)
    .body(Body::new(body))
    .expect("response body conversion should not fail");

  for (name, value) in &parts.headers {
    if !is_hop_by_hop(name) {
      out.headers_mut().append(name.clone(), value.clone());
    }
  }

  out
}

fn json_response(status: StatusCode, value: serde_json::Value) -> Response<Body> {
  let body = Body::from(value.to_string());
  let mut response = Response::builder()
    .status(status)
    .header(header::CONTENT_TYPE, "application/json")
    .body(body)
    .expect("json response should build");
  response
    .headers_mut()
    .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
  response
}

fn extract_client_ip(
  headers: &axum::http::HeaderMap,
  remote: SocketAddr,
  trust_xff: bool,
) -> IpAddr {
  if trust_xff {
    let forwarded = headers
      .get("x-forwarded-for")
      .and_then(|v| v.to_str().ok())
      .and_then(|v| v.split(',').next())
      .map(str::trim);
    if let Some(value) = forwarded {
      if let Ok(ip) = value.parse::<IpAddr>() {
        return ip;
      }
    }
  }
  remote.ip()
}

fn build_upstream_uri(upstream_addr: &str, original_uri: &Uri) -> anyhow::Result<Uri> {
  let path_and_query = original_uri
    .path_and_query()
    .map(|v| v.as_str())
    .unwrap_or("/");
  let base = if upstream_addr.starts_with("http://") || upstream_addr.starts_with("https://") {
    upstream_addr.to_string()
  } else {
    format!("http://{upstream_addr}")
  };
  let uri = format!("{}{}", base.trim_end_matches('/'), path_and_query).parse()?;
  Ok(uri)
}

fn copy_forward_headers(
  source: axum::http::HeaderMap,
  target: &mut axum::http::HeaderMap,
  upstream_addr: &str,
) {
  for (name, value) in &source {
    if !is_hop_by_hop(name) {
      target.append(name.clone(), value.clone());
    }
  }

  if let Some(host) = upstream_host(upstream_addr) {
    if let Ok(value) = HeaderValue::from_str(host) {
      target.insert(header::HOST, value);
    }
  }
}

fn upstream_host(addr: &str) -> Option<&str> {
  addr
    .strip_prefix("http://")
    .or_else(|| addr.strip_prefix("https://"))
    .or(Some(addr))
}

fn is_hop_by_hop(name: &HeaderName) -> bool {
  let value = name.as_str();
  value.eq_ignore_ascii_case("connection")
    || value.eq_ignore_ascii_case("keep-alive")
    || value.eq_ignore_ascii_case("proxy-authenticate")
    || value.eq_ignore_ascii_case("proxy-authorization")
    || value.eq_ignore_ascii_case("te")
    || value.eq_ignore_ascii_case("trailer")
    || value.eq_ignore_ascii_case("transfer-encoding")
    || value.eq_ignore_ascii_case("upgrade")
}

fn lb_algorithm_label(algo: &LbAlgorithm) -> &'static str {
  match algo {
    LbAlgorithm::RoundRobin => "round_robin",
    LbAlgorithm::WeightedRoundRobin => "weighted_round_robin",
    LbAlgorithm::LeastConnections => "least_connections",
  }
}

fn decision_label(decision: &Decision) -> &'static str {
  match decision {
    Decision::Allow => "allow",
    Decision::Block { .. } => "block",
    Decision::Log { .. } => "log",
    Decision::RateLimit { .. } => "rate_limit",
  }
}

fn should_record_attack_event(ctx: &RequestContext, decision: &Decision) -> bool {
  decision.is_blocking() || !ctx.threat_tags.is_empty()
}

fn log_layer_execution(
  mode: &'static str,
  context: &RequestContext,
  timings: &[nexus_pipeline::LayerTiming],
) {
  for timing in timings {
    tracing::info!(
      mode = mode,
      request_id = %context.id,
      layer = timing.name,
      decision = decision_label(&timing.decision),
      duration_us = timing.duration.as_micros(),
      "pipeline layer execution"
    );
  }
}

fn log_pipeline_outcome(
  mode: &'static str,
  context: &RequestContext,
  result: &nexus_pipeline::RunResult,
) {
  tracing::info!(
    mode = mode,
    request_id = %context.id,
    decision = decision_label(&result.decision),
    decided_by = result.decided_by.as_deref().unwrap_or("none"),
    risk_score = result.final_risk_score,
    layers_executed = result.timings.len(),
    total_duration_us = result.total_duration.as_micros(),
    "pipeline final decision"
  );
}
