use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::watch;
use tokio::time::interval;
use tracing::{error, info, warn};

use crate::loader::ConfigLoader;
use crate::schema::Config;

/// Watches a config file for changes and broadcasts the new config
/// to all subscribers via a `tokio::sync::watch` channel.
///
/// Uses polling (checks mtime every `poll_interval`) rather than
/// inotify, for portability across Linux, macOS, and containers.
pub struct ConfigWatcher {
  path: PathBuf,
  poll_interval: Duration,
  sender: watch::Sender<Arc<Config>>,
}

impl ConfigWatcher {
  pub fn new(
    path: PathBuf,
    initial_config: Arc<Config>,
    poll_interval: Duration,
  ) -> (Self, watch::Receiver<Arc<Config>>) {
    let (sender, receiver) = watch::channel(initial_config);
    let watcher = Self {
      path,
      poll_interval,
      sender,
    };
    (watcher, receiver)
  }
  pub async fn run(self) {
    let mut ticker = interval(self.poll_interval);
    let mut last_mtime = self.current_mtime();

    info!(
        path = %self.path.display(),
        interval_ms = self.poll_interval.as_millis(),
        "Config watcher started"
    );

    loop {
      ticker.tick().await;

      let current_mtime = self.current_mtime();
      if current_mtime <= last_mtime {
        continue;
      }

      info!(path = %self.path.display(), "Config file changed, reloading");
      last_mtime = current_mtime;

      match ConfigLoader::from_file(&self.path) {
        Ok(new_config) => {
          let new_config = Arc::new(new_config);
          if self.sender.send(new_config).is_err() {
            warn!("Config watcher: all receivers dropped, stopping");
            return;
          }
          info!("Config reloaded successfully");
        }
        Err(e) => {
          error!(error = %e, "Config reload failed — keeping current config");
        }
      }
    }
  }

  fn current_mtime(&self) -> u64 {
    std::fs::metadata(&self.path)
      .and_then(|m| m.modified())
      .map(|t| {
        t.duration_since(std::time::UNIX_EPOCH)
          .unwrap_or_default()
          .as_secs()
      })
      .unwrap_or(0)
  }
}

pub type LiveConfig = watch::Receiver<Arc<Config>>;
