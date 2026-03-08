use std::sync::Arc;

use axum::{
  extract::State,
  http::{header, Request, StatusCode},
  middleware::Next,
  response::{IntoResponse, Response},
  Json,
};
use subtle::ConstantTimeEq;

/// Validates `Authorization: Bearer <token>` in constant time.
pub async fn require_auth(
  State(expected_token): State<Arc<String>>,
  req: Request<axum::body::Body>,
  next: Next,
) -> Response {
  let provided = req
    .headers()
    .get(header::AUTHORIZATION)
    .and_then(|v| v.to_str().ok())
    .and_then(|v| v.strip_prefix("Bearer "))
    .unwrap_or("");

  if !constant_time_eq(provided, &expected_token) {
    return (
      StatusCode::UNAUTHORIZED,
      Json(serde_json::json!({ "error": "Invalid or missing token" })),
    )
      .into_response();
  }

  next.run(req).await
}

fn constant_time_eq(provided: &str, expected: &str) -> bool {
  provided.as_bytes().ct_eq(expected.as_bytes()).unwrap_u8() == 1
}

#[cfg(test)]
mod tests {
  use std::sync::Arc;

  use super::{constant_time_eq, require_auth};
  use axum::body::Body;
  use axum::http::{Request, StatusCode};
  use axum::{middleware, routing::get, Router};
  use tower::util::ServiceExt;

  #[test]
  fn constant_time_eq_matches_correct_values() {
    assert!(constant_time_eq("abc", "abc"));
    assert!(!constant_time_eq("abc", "abd"));
    assert!(!constant_time_eq("abc", "ab"));
  }

  #[tokio::test]
  async fn middleware_rejects_missing_token() {
    let app = Router::new()
      .route("/api/stats", get(|| async { "ok" }))
      .layer(middleware::from_fn_with_state(
        Arc::new("secret".to_string()),
        require_auth,
      ));

    let response = app
      .oneshot(
        Request::builder()
          .uri("/api/stats")
          .body(Body::empty())
          .unwrap(),
      )
      .await
      .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
  }

  #[tokio::test]
  async fn middleware_accepts_valid_token() {
    let app = Router::new()
      .route("/api/stats", get(|| async { "ok" }))
      .layer(middleware::from_fn_with_state(
        Arc::new("secret".to_string()),
        require_auth,
      ));

    let response = app
      .oneshot(
        Request::builder()
          .uri("/api/stats")
          .header("Authorization", "Bearer secret")
          .body(Body::empty())
          .unwrap(),
      )
      .await
      .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
  }
}
