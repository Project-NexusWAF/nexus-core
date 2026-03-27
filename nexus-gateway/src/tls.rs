use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Context};
use axum::{
  extract::{Path as AxumPath, State},
  http::{header, HeaderValue, StatusCode},
  response::IntoResponse,
  routing::get,
  Router,
};
use axum_server::tls_rustls::RustlsConfig;
use nexus_config::{CertbotConfig, Config, SlackSeverity, TlsConfig};
use tokio::process::Command;

use crate::state::AppState;

pub struct PreparedTls {
  pub rustls: Option<RustlsConfig>,
  pub challenge_handle: Option<tokio::task::JoinHandle<anyhow::Result<()>>>,
}

#[derive(Clone)]
struct AcmeChallengeState {
  webroot_dir: Arc<PathBuf>,
}

#[derive(Clone)]
struct ResolvedTlsFiles {
  cert_path: String,
  key_path: String,
}

pub async fn prepare_tls(state: Arc<AppState>) -> anyhow::Result<PreparedTls> {
  let cfg = state.active_config();
  if !cfg.gateway.tls.enabled {
    return Ok(PreparedTls {
      rustls: None,
      challenge_handle: None,
    });
  }

  let challenge_handle = if cfg.gateway.tls.certbot.enabled {
    Some(start_acme_challenge_server(&cfg).await?)
  } else {
    None
  };

  if cfg.gateway.tls.certbot.enabled {
    ensure_certbot_certificate(&cfg.gateway.tls).await?;
  }

  let resolved = resolve_tls_files(&cfg.gateway.tls);
  let rustls = RustlsConfig::from_pem_file(&resolved.cert_path, &resolved.key_path)
    .await
    .with_context(|| {
      format!(
        "failed to load TLS certificate from {} and {}",
        resolved.cert_path, resolved.key_path
      )
    })?;

  spawn_tls_reload_task(Arc::clone(&state), rustls.clone());
  if cfg.gateway.tls.certbot.enabled {
    spawn_certbot_renewal_task(state, rustls.clone());
  }

  Ok(PreparedTls {
    rustls: Some(rustls),
    challenge_handle,
  })
}

fn spawn_tls_reload_task(state: Arc<AppState>, rustls: RustlsConfig) {
  tokio::spawn(async move {
    let mut rx = state.control.live_config.clone();
    loop {
      if rx.changed().await.is_err() {
        tracing::warn!("config watcher channel closed; stopping TLS reload task");
        return;
      }

      let cfg = rx.borrow().clone();
      if !cfg.gateway.tls.enabled {
        tracing::warn!("live config disabled TLS; listener restart is required to turn HTTPS off");
        continue;
      }

      let resolved = resolve_tls_files(&cfg.gateway.tls);
      if let Err(error) = rustls
        .reload_from_pem_file(&resolved.cert_path, &resolved.key_path)
        .await
      {
        tracing::error!(error = %error, "failed to reload TLS certificate after config change");
        state.slack_alerts.notify_system(
          "TLS Reload Failed",
          format!("Certificate reload failed after config update: {error}"),
          SlackSeverity::High,
        );
      } else {
        tracing::info!(
          cert_path = %resolved.cert_path,
          key_path = %resolved.key_path,
          "reloaded TLS certificate after config change"
        );
      }
    }
  });
}

fn spawn_certbot_renewal_task(state: Arc<AppState>, rustls: RustlsConfig) {
  tokio::spawn(async move {
    loop {
      let interval = {
        let cfg = state.active_config();
        if !cfg.gateway.tls.enabled || !cfg.gateway.tls.certbot.enabled {
          Duration::from_secs(300)
        } else {
          Duration::from_secs(cfg.gateway.tls.certbot.renew_interval_hours.max(1) * 60 * 60)
        }
      };

      tokio::time::sleep(interval).await;

      let cfg = state.active_config();
      if !cfg.gateway.tls.enabled || !cfg.gateway.tls.certbot.enabled {
        continue;
      }

      match ensure_certbot_certificate(&cfg.gateway.tls).await {
        Ok(()) => {
          let resolved = resolve_tls_files(&cfg.gateway.tls);
          match rustls
            .reload_from_pem_file(&resolved.cert_path, &resolved.key_path)
            .await
          {
            Ok(()) => tracing::info!("completed Certbot renewal check and TLS reload"),
            Err(error) => {
              tracing::error!(error = %error, "certificate renewed but TLS reload failed");
              state.slack_alerts.notify_system(
                "TLS Reload Failed",
                format!("Certbot completed but the HTTPS listener failed to reload the certificate: {error}"),
                SlackSeverity::High,
              );
            }
          }
        }
        Err(error) => {
          tracing::error!(error = %error, "Certbot renewal check failed");
          state.slack_alerts.notify_system(
            "TLS Renewal Failed",
            format!("Certbot renewal check failed: {error}"),
            SlackSeverity::High,
          );
        }
      }
    }
  });
}

async fn start_acme_challenge_server(
  cfg: &Config,
) -> anyhow::Result<tokio::task::JoinHandle<anyhow::Result<()>>> {
  let certbot = &cfg.gateway.tls.certbot;
  tokio::fs::create_dir_all(challenge_root(certbot))
    .await
    .with_context(|| {
      format!(
        "failed to create Certbot webroot {}",
        challenge_root(certbot).display()
      )
    })?;

  let listener = tokio::net::TcpListener::bind(&certbot.challenge_addr)
    .await
    .with_context(|| {
      format!(
        "failed to bind ACME challenge listener on {}",
        certbot.challenge_addr
      )
    })?;

  let state = AcmeChallengeState {
    webroot_dir: Arc::new(PathBuf::from(&certbot.webroot_dir)),
  };
  let router = Router::new()
    .route("/.well-known/acme-challenge/:token", get(acme_challenge_handler))
    .with_state(state);

  tracing::info!(
    addr = %certbot.challenge_addr,
    webroot = %certbot.webroot_dir,
    "ACME challenge listener ready for Certbot"
  );

  Ok(tokio::spawn(async move {
    axum::serve(listener, router)
      .await
      .context("ACME challenge server failed")
  }))
}

async fn acme_challenge_handler(
  State(state): State<AcmeChallengeState>,
  AxumPath(token): AxumPath<String>,
) -> impl IntoResponse {
  if !is_safe_challenge_token(&token) {
    return (
      StatusCode::BAD_REQUEST,
      "invalid ACME challenge token".to_string(),
    )
      .into_response();
  }

  let path = challenge_file_path(state.webroot_dir.as_ref(), &token);
  match tokio::fs::read_to_string(&path).await {
    Ok(content) => {
      let headers = [(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
      )];
      (StatusCode::OK, headers, content).into_response()
    }
    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
      (StatusCode::NOT_FOUND, "challenge token not found".to_string()).into_response()
    }
    Err(error) => {
      tracing::warn!(error = %error, path = %path.display(), "failed to read ACME challenge file");
      (
        StatusCode::INTERNAL_SERVER_ERROR,
        "failed to read challenge token".to_string(),
      )
        .into_response()
    }
  }
}

fn is_safe_challenge_token(token: &str) -> bool {
  !token.is_empty()
    && token
      .chars()
      .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
}

fn resolve_tls_files(cfg: &TlsConfig) -> ResolvedTlsFiles {
  let cert_name = resolved_cert_name(&cfg.certbot);
  let cert_path = if cfg.cert_path.trim().is_empty() && cfg.certbot.enabled {
    PathBuf::from(&cfg.certbot.live_dir)
      .join(&cert_name)
      .join("fullchain.pem")
      .to_string_lossy()
      .to_string()
  } else {
    cfg.cert_path.clone()
  };
  let key_path = if cfg.key_path.trim().is_empty() && cfg.certbot.enabled {
    PathBuf::from(&cfg.certbot.live_dir)
      .join(&cert_name)
      .join("privkey.pem")
      .to_string_lossy()
      .to_string()
  } else {
    cfg.key_path.clone()
  };

  ResolvedTlsFiles { cert_path, key_path }
}

async fn ensure_certbot_certificate(tls_cfg: &TlsConfig) -> anyhow::Result<()> {
  let certbot = &tls_cfg.certbot;
  if !certbot.enabled {
    return Ok(());
  }

  tokio::fs::create_dir_all(challenge_root(certbot))
    .await
    .with_context(|| {
      format!(
        "failed to create Certbot challenge directory {}",
        challenge_root(certbot).display()
      )
    })?;

  let cert_name = resolved_cert_name(certbot);
  let mut cmd = Command::new(&certbot.certbot_bin);
  cmd.arg("certonly")
    .arg("--webroot")
    .arg("-w")
    .arg(&certbot.webroot_dir)
    .arg("--non-interactive")
    .arg("--agree-tos")
    .arg("--keep-until-expiring")
    .arg("--preferred-challenges")
    .arg("http")
    .arg("--cert-name")
    .arg(&cert_name)
    .arg("-m")
    .arg(&certbot.email)
    .arg("-d")
    .arg(&certbot.domain);

  for domain in &certbot.extra_domains {
    cmd.arg("-d").arg(domain);
  }

  if certbot.staging {
    cmd.arg("--staging");
  }

  let output = cmd
    .output()
    .await
    .with_context(|| format!("failed to execute {}", certbot.certbot_bin))?;

  if !output.status.success() {
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let detail = if !stderr.is_empty() {
      stderr
    } else if !stdout.is_empty() {
      stdout
    } else {
      "Certbot exited without an error message".to_string()
    };
    bail!("Certbot failed for certificate {cert_name}: {detail}");
  }

  let resolved = resolve_tls_files(tls_cfg);
  if tokio::fs::metadata(&resolved.cert_path).await.is_err() {
    return Err(anyhow!(
      "Certbot completed but {} was not found",
      resolved.cert_path
    ));
  }
  if tokio::fs::metadata(&resolved.key_path).await.is_err() {
    return Err(anyhow!(
      "Certbot completed but {} was not found",
      resolved.key_path
    ));
  }

  tracing::info!(cert_name = %cert_name, "Certbot certificate check completed");
  Ok(())
}

fn resolved_cert_name(certbot: &CertbotConfig) -> String {
  if !certbot.cert_name.trim().is_empty() {
    certbot.cert_name.trim().to_string()
  } else {
    certbot.domain.trim().to_string()
  }
}

fn challenge_root(certbot: &CertbotConfig) -> PathBuf {
  PathBuf::from(&certbot.webroot_dir)
    .join(".well-known")
    .join("acme-challenge")
}

fn challenge_file_path(webroot_dir: &std::path::Path, token: &str) -> PathBuf {
  webroot_dir
    .join(".well-known")
    .join("acme-challenge")
    .join(token)
}
