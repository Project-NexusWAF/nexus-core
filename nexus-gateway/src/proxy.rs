use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use axum::body::{to_bytes, Body};
use axum::extract::{ConnectInfo, Query, State};
use axum::http::header::{self, HeaderMap, HeaderName, HeaderValue};
use axum::http::{Method, Request, Response, StatusCode, Uri, Version};
use bytes::Bytes;
use http_body_util::Full;
use nexus_common::{Decision, RequestContext};
use serde::Deserialize;

use crate::state::AppState;

const DEMO_HTML: &str = include_str!("../assets/demo.html");

#[derive(Debug, Deserialize)]
pub struct DemoCheckQuery {
  pub case: Option<String>,
  pub method: Option<String>,
  pub path: Option<String>,
  pub body: Option<String>,
}

#[derive(Debug, Clone)]
struct DemoPayload {
  case_id: String,
  method: Method,
  path: String,
  body: String,
}

pub async fn demo_page() -> Response<Body> {
  let mut response = Response::builder()
    .status(StatusCode::OK)
    .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
    .body(Body::from(DEMO_HTML))
    .expect("demo page response should build");
  response
    .headers_mut()
    .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
  response
}

pub async fn demo_check_handler(
  State(state): State<Arc<AppState>>,
  ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
  Query(query): Query<DemoCheckQuery>,
) -> Response<Body> {
  let payload = match resolve_demo_payload(query) {
    Ok(payload) => payload,
    Err(error) => {
      return json_response(
        StatusCode::BAD_REQUEST,
        serde_json::json!({
          "message": error,
        }),
      );
    }
  };
  let uri = match format!("http://demo.local{}", payload.path).parse::<Uri>() {
    Ok(uri) => uri,
    Err(error) => {
      return json_response(
        StatusCode::BAD_REQUEST,
        serde_json::json!({
          "message": format!("invalid path for demo case: {error}")
        }),
      );
    }
  };

  let mut headers = HeaderMap::new();
  if !payload.body.is_empty() {
    headers.insert(
      header::CONTENT_TYPE,
      HeaderValue::from_static("text/plain; charset=utf-8"),
    );
  }

  let mut context = RequestContext::new(
    remote_addr.ip(),
    payload.method.clone(),
    uri,
    Version::HTTP_11,
    headers,
    Bytes::from(payload.body.clone()),
  );

  let pipeline = state.clone_pipeline();
  let result = pipeline.run(&mut context).await;
  log_layer_execution("demo", &context, &result.timings);
  log_pipeline_outcome("demo", &context, &result);

  state.control.requests_total.fetch_add(1, Ordering::Relaxed);
  if result.is_blocked() {
    if matches!(result.decision, Decision::RateLimit { .. }) {
      state
        .control
        .rate_limited_total
        .fetch_add(1, Ordering::Relaxed);
    } else {
      state.control.blocked_total.fetch_add(1, Ordering::Relaxed);
    }
  }

  if should_record_attack_event(&context, &result.decision) {
    if let Some(writer) = &state.control.log_writer {
      let event = nexus_store::BlockedEvent::from_context(&context, &result.decision);
      writer.record(event);
    }
  }

  let blocked_by = result.decided_by.unwrap_or("none");
  let decision_text = decision_label(&result.decision);
  let message = match &result.decision {
    Decision::Block { reason, .. } => format!("Blocked by {blocked_by}: {reason}"),
    Decision::RateLimit {
      retry_after_seconds,
    } => format!("Rate-limited by {blocked_by}; retry after {retry_after_seconds}s"),
    _ => "Allowed by pipeline. Demo mode intentionally skips upstream forwarding.".to_string(),
  };

  let layer_timings = result
    .timings
    .iter()
    .map(|timing| {
      serde_json::json!({
        "layer": timing.name,
        "decision": decision_label(&timing.decision),
        "duration_us": timing.duration.as_micros(),
      })
    })
    .collect::<Vec<_>>();

  let status = match result.decision {
    Decision::Block { .. } => StatusCode::FORBIDDEN,
    Decision::RateLimit { .. } => StatusCode::TOO_MANY_REQUESTS,
    _ => StatusCode::OK,
  };
  let blocked = status != StatusCode::OK;
  let mut threat_tags: Vec<String> = context.threat_tags.iter().cloned().collect();
  threat_tags.sort();
  let total_duration_us = result.total_duration.as_micros();
  let risk_score = result.final_risk_score;
  let layers_executed = result.timings.len();
  let decided_by = result.decided_by;
  let flagged_by = context.flagged_by.clone();
  let request_uri = context.uri.clone();
  let request_ip = context.client_ip.to_string();
  let method = payload.method.to_string();
  let path = payload.path.clone();
  let body = payload.body.clone();

  let mut response = json_response(
    status,
    serde_json::json!({
      "status_code": status.as_u16(),
      "case": payload.case_id,
      "method": method.clone(),
      "path": path.clone(),
      "blocked": blocked,
      "decision": decision_text,
      "blocked_by": blocked_by,
      "message": message,
      "final_risk_score": risk_score,
      "layer_timings": layer_timings,
      "request": {
        "method": method,
        "path": path,
        "uri": request_uri,
        "body": body,
        "body_bytes": context.body.len(),
        "client_ip": request_ip,
      },
      "analysis": {
        "http_status": status.as_u16(),
        "decision": decision_text,
        "blocked": blocked,
        "blocked_by": blocked_by,
        "message": message,
        "risk_score": risk_score,
        "threat_tags": threat_tags,
        "flagged_by": flagged_by,
        "layers_executed": layers_executed,
        "total_duration_us": total_duration_us,
        "decided_by": decided_by,
      }
    }),
  );
  response
    .headers_mut()
    .insert("x-demo-mode", HeaderValue::from_static("true"));
  response
}

pub async fn proxy_handler(
  State(state): State<Arc<AppState>>,
  ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
  request: Request<Body>,
) -> Response<Body> {
  let cfg = state.active_config();
  let max_body_bytes = cfg.gateway.max_body_bytes;
  let request_timeout = Duration::from_millis(cfg.gateway.request_timeout_ms);
  let trust_xff = cfg.gateway.trust_x_forwarded_for;
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
  if should_record_attack_event(&context, &result.decision) {
    if let Some(writer) = &state.control.log_writer {
      let event = nexus_store::BlockedEvent::from_context(&context, &result.decision);
      writer.record(event);
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

    return block_response(result.decision, result.decided_by);
  }

  let Some(upstream) = state.select_upstream() else {
    return json_response(
      StatusCode::BAD_GATEWAY,
      serde_json::json!({ "error": "no healthy upstream available" }),
    );
  };

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

  match tokio::time::timeout(request_timeout, state.http_client.request(outbound)).await {
    Ok(Ok(upstream_response)) => map_upstream_response(upstream_response),
    Ok(Err(error)) => {
      tracing::warn!(error = %error, "upstream request failed");
      json_response(
        StatusCode::BAD_GATEWAY,
        serde_json::json!({ "error": "upstream request failed" }),
      )
    }
    Err(_) => json_response(
      StatusCode::GATEWAY_TIMEOUT,
      serde_json::json!({ "error": "upstream timeout" }),
    ),
  }
}

fn block_response(decision: Decision, decided_by: Option<&'static str>) -> Response<Body> {
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

fn resolve_demo_payload(query: DemoCheckQuery) -> Result<DemoPayload, String> {
  if let Some(case_id) = query.case {
    return preset_case(&case_id).ok_or_else(|| format!("unknown preset case '{case_id}'"));
  }

  let method = parse_method(query.method.as_deref().unwrap_or("GET"));
  let path = normalise_path(query.path.as_deref().unwrap_or("/"));
  let body = query.body.unwrap_or_default();
  Ok(DemoPayload {
    case_id: "custom".to_string(),
    method,
    path,
    body,
  })
}

fn preset_case(case_id: &str) -> Option<DemoPayload> {
  let preset = match case_id {
    "allow_home" => ("GET", "/", ""),
    "allow_search" => ("GET", "/search?q=books&category=security", ""),
    "allow_profile_update" => ("POST", "/profile/update", "name=alice&city=mumbai"),
    "block_rules_admin" => ("GET", "/admin/panel", ""),
    "block_grammar_xss" => ("POST", "/comments", "<script>alert('xss')</script>"),
    "block_grammar_sqli" => (
      "POST",
      "/query",
      "1 UNION SELECT username, password FROM users",
    ),
    // Path-based SQLi for clear visual demo in the UI Path field.
    "block_sqli" => ("GET", "/login?user=admin+OR+1=1--", ""),
    "block_xss" => ("POST", "/comments", "<script>alert('xss')</script>"),
    "block_path_traversal" => ("GET", "/download?file=../../etc/passwd", ""),
    "block_cmd_injection" => ("GET", "/exec?cmd=cat+/etc/passwd;id", ""),
    _ => return None,
  };

  Some(DemoPayload {
    case_id: case_id.to_string(),
    method: parse_method(preset.0),
    path: preset.1.to_string(),
    body: preset.2.to_string(),
  })
}

fn parse_method(method: &str) -> Method {
  Method::from_bytes(method.as_bytes()).unwrap_or(Method::GET)
}

fn normalise_path(path: &str) -> String {
  let trimmed = path.trim();
  if trimmed.is_empty() {
    return "/".to_string();
  }
  if trimmed.starts_with('/') {
    return trimmed.to_string();
  }
  format!("/{trimmed}")
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
    decided_by = result.decided_by.unwrap_or("none"),
    risk_score = result.final_risk_score,
    layers_executed = result.timings.len(),
    total_duration_us = result.total_duration.as_micros(),
    "pipeline final decision"
  );
}
