use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Context};
use rand::RngCore;
use sha2::{Digest, Sha256};

use nexus_config::{Config, ConfigLoader, ConfigWatcher};
#[cfg(unix)]
use nexus_pipeline::PipelineBuilder;

use crate::server;
use crate::state::AppState;

pub async fn cmd_start(config_path: String, listen_override: Option<String>) -> anyhow::Result<()> {
  server::init_tracing();

  let config = Arc::new(
    ConfigLoader::from_file(&config_path)
      .with_context(|| format!("failed to load config from {config_path}"))?,
  );
  let config = apply_listen_override(config, listen_override);

  write_pid(&config.gateway.pid_file)?;
  let admin_token = resolve_token(&config);

  let (watcher, live_config) = ConfigWatcher::new(
    PathBuf::from(&config_path),
    Arc::clone(&config),
    Duration::from_secs(10),
  );
  tokio::spawn(watcher.run());

  let state = AppState::new(Arc::clone(&config), live_config, admin_token)
    .await
    .context("failed to build application state")?;
  server::spawn_config_reload_task(Arc::clone(&state));

  #[cfg(unix)]
  spawn_sighup_handler(config_path.clone(), Arc::clone(&state));

  let proxy_handle = tokio::spawn(server::run_gateway(
    config.gateway.listen_addr.clone(),
    Arc::clone(&state),
  ));
  let grpc_handle = tokio::spawn(server::run_grpc(
    config.gateway.control_addr.clone(),
    Arc::clone(&state),
  ));
  let rest_handle = tokio::spawn(server::run_rest(
    config.gateway.rest_addr.clone(),
    Arc::clone(&state),
  ));
  let metrics_handle = tokio::spawn(nexus_metrics::serve_metrics(
    config.gateway.metrics_addr.clone(),
  ));

  let run_result: anyhow::Result<()> = tokio::select! {
    res = proxy_handle => {
      res.context("gateway task failed to join")??;
      Ok(())
    }
    res = grpc_handle => {
      res.context("gRPC task failed to join")??;
      Ok(())
    }
    res = rest_handle => {
      res.context("REST task failed to join")??;
      Ok(())
    }
    res = metrics_handle => {
      res.context("metrics task failed to join")??;
      Ok(())
    }
    _ = shutdown_signal() => {
      tracing::info!("shutdown signal received");
      Ok(())
    }
  };

  let _ = std::fs::remove_file(&config.gateway.pid_file);
  run_result
}

pub async fn cmd_stop(config_path: String) -> anyhow::Result<()> {
  let config = ConfigLoader::from_file(&config_path)?;
  let pid = read_pid(&config.gateway.pid_file)
    .with_context(|| format!("failed to read pid file {}", config.gateway.pid_file))?;

  #[cfg(unix)]
  {
    use nix::sys::signal::{kill, Signal};
    kill(nix::unistd::Pid::from_raw(pid), Signal::SIGTERM)?;
    println!("Sent SIGTERM to PID {pid}");
    return Ok(());
  }

  #[cfg(not(unix))]
  {
    let _ = pid;
    bail!("cmd stop is only supported on Unix targets");
  }
}

pub async fn cmd_reload(config_path: String) -> anyhow::Result<()> {
  let config = ConfigLoader::from_file(&config_path)?;
  let pid = read_pid(&config.gateway.pid_file)
    .with_context(|| format!("failed to read pid file {}", config.gateway.pid_file))?;

  #[cfg(unix)]
  {
    use nix::sys::signal::{kill, Signal};
    kill(nix::unistd::Pid::from_raw(pid), Signal::SIGHUP)?;
    println!("Sent SIGHUP to PID {pid}");
    return Ok(());
  }

  #[cfg(not(unix))]
  {
    let _ = pid;
    bail!("cmd reload is only supported on Unix targets");
  }
}

pub async fn cmd_status(config_path: String) -> anyhow::Result<()> {
  let config = ConfigLoader::from_file(&config_path)?;
  let url = format!("http://{}", normalise_local_addr(&config.gateway.rest_addr));
  let endpoint = format!("{url}/api/health");
  let client = reqwest::Client::builder()
    .timeout(Duration::from_secs(5))
    .build()?;

  match client.get(endpoint).send().await {
    Ok(response) if response.status().is_success() => {
      println!("RUNNING");
      println!("{}", response.text().await?);
      Ok(())
    }
    Ok(response) => {
      println!("UNHEALTHY ({})", response.status());
      bail!("status endpoint returned non-success code");
    }
    Err(error) => {
      println!("STOPPED or UNREACHABLE");
      Err(anyhow!(error))
    }
  }
}

pub async fn cmd_token(config_path: String) -> anyhow::Result<()> {
  let config = ConfigLoader::from_file(&config_path)?;

  if let Ok(token) = std::env::var("NEXUS_ADMIN_TOKEN") {
    if !token.trim().is_empty() {
      println!("Token source: env:NEXUS_ADMIN_TOKEN");
      println!("Token fingerprint: {}", token_fingerprint(&token));
      return Ok(());
    }
  }

  if let Some(token) = &config.gateway.auth_token {
    if !token.trim().is_empty() {
      println!("Token source: config.gateway.auth_token");
      println!("Token fingerprint: {}", token_fingerprint(token));
      return Ok(());
    }
  }

  println!("No static admin token configured.");
  println!("Startup will auto-generate an ephemeral token and print it once.");
  Ok(())
}

pub async fn cmd_check(config_path: String) -> anyhow::Result<()> {
  let config = ConfigLoader::from_file(&config_path)?;
  config.validate()?;

  println!("Config OK: {config_path}");
  println!("  proxy:    {}", config.gateway.listen_addr);
  println!("  grpc:     {}", config.gateway.control_addr);
  println!("  rest:     {}", config.gateway.rest_addr);
  println!("  metrics:  {}", config.gateway.metrics_addr);
  println!("  upstream: {} configured", config.lb.upstreams.len());
  Ok(())
}

fn apply_listen_override(config: Arc<Config>, listen_override: Option<String>) -> Arc<Config> {
  if let Some(addr) = listen_override {
    let mut updated = (*config).clone();
    updated.gateway.listen_addr = addr;
    Arc::new(updated)
  } else {
    config
  }
}

fn resolve_token(config: &Config) -> String {
  if let Ok(token) = std::env::var("NEXUS_ADMIN_TOKEN") {
    if !token.trim().is_empty() {
      return token;
    }
  }

  if let Some(token) = &config.gateway.auth_token {
    if !token.trim().is_empty() {
      return token.clone();
    }
  }

  let mut bytes = [0u8; 32];
  rand::rngs::OsRng.fill_bytes(&mut bytes);
  let token = bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();

  println!("============================================================");
  println!("NexusWAF Admin Token (shown once)");
  println!("{token}");
  println!("============================================================");

  token
}

fn token_fingerprint(token: &str) -> String {
  let digest = Sha256::digest(token.as_bytes());
  format!("{:x}", digest)[..12].to_string()
}

fn write_pid(path: &str) -> anyhow::Result<()> {
  let path = Path::new(path);
  if let Some(parent) = path.parent() {
    if !parent.as_os_str().is_empty() {
      std::fs::create_dir_all(parent)
        .with_context(|| format!("failed to create pid parent {}", parent.display()))?;
    }
  }

  std::fs::write(path, std::process::id().to_string())
    .with_context(|| format!("failed to write pid file {}", path.display()))?;
  Ok(())
}

fn read_pid(path: &str) -> anyhow::Result<i32> {
  let value =
    std::fs::read_to_string(path).with_context(|| format!("failed to read pid file {path}"))?;
  let pid = value
    .trim()
    .parse::<i32>()
    .with_context(|| format!("invalid pid value in {path}"))?;
  Ok(pid)
}

fn normalise_local_addr(addr: &str) -> String {
  addr
    .replace("0.0.0.0", "127.0.0.1")
    .replace("[::]", "127.0.0.1")
}

async fn shutdown_signal() {
  #[cfg(unix)]
  {
    use tokio::signal::unix::{signal, SignalKind};
    let mut terminate = signal(SignalKind::terminate()).expect("failed to register SIGTERM");
    tokio::select! {
      _ = tokio::signal::ctrl_c() => {}
      _ = terminate.recv() => {}
    }
  }

  #[cfg(not(unix))]
  {
    let _ = tokio::signal::ctrl_c().await;
  }
}

#[cfg(unix)]
fn spawn_sighup_handler(config_path: String, state: Arc<AppState>) {
  use tokio::signal::unix::{signal, SignalKind};
  tokio::spawn(async move {
    let mut hup = match signal(SignalKind::hangup()) {
      Ok(signal) => signal,
      Err(error) => {
        tracing::error!(error = %error, "failed to register SIGHUP handler");
        return;
      }
    };

    while hup.recv().await.is_some() {
      tracing::info!("SIGHUP received, reloading pipeline from config file");
      match ConfigLoader::from_file(&config_path) {
        Ok(cfg) => {
          let pipeline = PipelineBuilder::from_config(&cfg);
          if let Err(error) = pipeline.init().await {
            tracing::error!(error = %error, "reload failed during pipeline init");
            continue;
          }
          *state.control.pipeline.write() = pipeline;
          let version = state
            .control
            .config_version
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
            + 1;
          tracing::info!(config_version = version, "pipeline reloaded from SIGHUP");
        }
        Err(error) => {
          tracing::error!(error = %error, "reload failed: invalid config file");
        }
      }
    }
  });
}

#[cfg(test)]
mod tests {
  use super::{resolve_token, token_fingerprint};
  use nexus_config::ConfigLoader;
  use std::sync::{Mutex, MutexGuard};

  static ENV_LOCK: Mutex<()> = Mutex::new(());

  fn env_lock() -> MutexGuard<'static, ()> {
    ENV_LOCK.lock().expect("env lock should not be poisoned")
  }

  fn config_with_token(token: Option<&str>) -> nexus_config::Config {
    let mut config = ConfigLoader::from_str(
      r#"
[gateway]
listen_addr = "0.0.0.0:8080"
control_addr = "0.0.0.0:9090"
rest_addr = "0.0.0.0:9091"
metrics_addr = "0.0.0.0:9092"
pid_file = "nexus.pid"

[pipeline]

[rate]

[lexical]

[lb]
upstreams = [{ name = "backend-1", addr = "127.0.0.1:3000" }]

[rules]
rules_file = "config/rules.toml"
"#,
    )
    .expect("config should parse");
    config.gateway.auth_token = token.map(str::to_string);
    config
  }

  #[test]
  fn resolve_token_prefers_env_var() {
    let _guard = env_lock();
    std::env::set_var("NEXUS_ADMIN_TOKEN", "from-env");
    let cfg = config_with_token(Some("from-config"));
    let token = resolve_token(&cfg);
    assert_eq!(token, "from-env");
    std::env::remove_var("NEXUS_ADMIN_TOKEN");
  }

  #[test]
  fn resolve_token_falls_back_to_config() {
    let _guard = env_lock();
    std::env::remove_var("NEXUS_ADMIN_TOKEN");
    let cfg = config_with_token(Some("from-config"));
    let token = resolve_token(&cfg);
    assert_eq!(token, "from-config");
  }

  #[test]
  fn token_fingerprint_is_redacted_summary() {
    let fp = token_fingerprint("very-secret-value");
    assert_eq!(fp.len(), 12);
    assert!(fp.chars().all(|c| c.is_ascii_hexdigit()));
  }
}
