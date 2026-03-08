use std::time::{Duration, Instant};

use crate::circuit_breaker::CircuitBreaker;
use crate::result::MlResult;

pub struct MlClient {
  endpoint: String,
  timeout: Duration,
  breaker: std::sync::Arc<CircuitBreaker>,
}

impl MlClient {
  pub fn new(endpoint: String, timeout_ms: u64) -> Self {
    Self {
      endpoint,
      timeout: Duration::from_millis(timeout_ms),
      breaker: CircuitBreaker::new(5, Duration::from_secs(30)),
    }
  }

  pub fn from_config(cfg: &nexus_config::MlConfig) -> Self {
    Self::new(cfg.endpoint.clone(), cfg.timeout_ms)
  }

  pub fn endpoint(&self) -> &str {
    &self.endpoint
  }

  pub async fn classify(&self, ctx: &nexus_common::RequestContext) -> MlResult {
    if self.breaker.is_open() {
      return MlResult::unavailable("circuit open", Duration::ZERO);
    }

    let start = Instant::now();
    let text = self.build_text(ctx);
    let request_id = ctx.id.to_string();

    match self.send(text, request_id).await {
      Ok(resp) => {
        self.breaker.record_success();
        MlResult {
          score: resp.score,
          label: resp.label,
          available: true,
          duration: start.elapsed(),
        }
      }
      Err(e) => {
        self.breaker.record_failure();
        MlResult::unavailable(&e, start.elapsed())
      }
    }
  }

  fn build_text(&self, ctx: &nexus_common::RequestContext) -> String {
    let body = std::str::from_utf8(&ctx.body).unwrap_or("");
    let raw = format!("{}\n{}", ctx.uri, body);
    raw.chars().take(4096).collect()
  }

  async fn send(
    &self,
    text: String,
    request_id: String,
  ) -> std::result::Result<crate::proto::InferenceResponse, String> {
    use crate::proto::inference_service_client::InferenceServiceClient;
    use crate::proto::InferenceRequest;

    let mut client = tokio::time::timeout(
      self.timeout,
      InferenceServiceClient::connect(self.endpoint.clone()),
    )
    .await
    .map_err(|_| "connection timeout".to_string())?
    .map_err(|e| e.to_string())?;

    let req = tonic::Request::new(InferenceRequest { text, request_id });
    let resp = tokio::time::timeout(self.timeout, client.classify(req))
      .await
      .map_err(|_| "inference timeout".to_string())?
      .map_err(|e| e.to_string())?;

    Ok(resp.into_inner())
  }
}

#[cfg(test)]
mod tests {
  use super::MlClient;
  use bytes::Bytes;
  use http::{HeaderMap, Method, Version};
  use nexus_common::RequestContext;
  use std::net::{IpAddr, Ipv4Addr};

  fn make_ctx(uri: &str, body: Vec<u8>) -> RequestContext {
    RequestContext::new(
      IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
      Method::POST,
      uri.parse().expect("valid uri"),
      Version::HTTP_11,
      HeaderMap::new(),
      Bytes::from(body),
    )
  }

  #[test]
  fn build_text_truncates_to_4096_chars() {
    let client = MlClient::new("http://127.0.0.1:50051".into(), 1000);
    let body = vec![b'a'; 5000];
    let ctx = make_ctx("http://example.com/path", body);

    let text = client.build_text(&ctx);
    assert_eq!(text.chars().count(), 4096);
  }

  #[test]
  fn build_text_handles_non_utf8_body_without_panic() {
    let client = MlClient::new("http://127.0.0.1:50051".into(), 1000);
    let uri = "http://example.com/path";
    let ctx = make_ctx(uri, vec![0xff, 0xfe, 0xfd, 0x00]);

    let text = client.build_text(&ctx);
    assert_eq!(text, format!("{uri}\n"));
  }
}
