use axum::{
  http::{StatusCode, Uri},
  response::{IntoResponse, Response},
};

#[derive(rust_embed::RustEmbed)]
#[folder = "assets/"]
struct DashboardAssets;

pub async fn serve_dashboard(uri: Uri) -> Response {
  let mut path = uri.path().trim_start_matches('/');
  if path.is_empty() {
    path = "index.html";
  }

  // Reject unsafe path patterns before touching the embedded asset store.
  if path.contains("..") || path.contains('\\') {
    return StatusCode::NOT_FOUND.into_response();
  }

  if let Some(content) = DashboardAssets::get(path) {
    let mime = mime_guess::from_path(path).first_or_octet_stream();
    return (
      [(axum::http::header::CONTENT_TYPE, mime.as_ref().to_owned())],
      content.data.to_vec(),
    )
      .into_response();
  }

  if let Some(index) = DashboardAssets::get("index.html") {
    return (
      [(axum::http::header::CONTENT_TYPE, "text/html".to_owned())],
      index.data.to_vec(),
    )
      .into_response();
  }

  StatusCode::NOT_FOUND.into_response()
}

#[cfg(test)]
mod tests {
  use super::serve_dashboard;
  use axum::http::{StatusCode, Uri};

  #[tokio::test]
  async fn serves_index_on_root() {
    let response = serve_dashboard(Uri::from_static("/")).await;
    assert_eq!(response.status(), StatusCode::OK);
  }

  #[tokio::test]
  async fn fallback_serves_index_for_unknown_path() {
    let response = serve_dashboard(Uri::from_static("/app/dashboard")).await;
    assert_eq!(response.status(), StatusCode::OK);
  }
}
