use std::{sync::Arc, time::Duration};
use tokio::{net::TcpStream, time::{self, timeout}};
use crate::balancer::LoadBalancer;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

pub async fn run_health_checks(lb: Arc<LoadBalancer>, interval: Duration) {
    let mut ticker = time::interval(interval);

    loop {
        ticker.tick().await;

        let addrs: Vec<String> = lb
            .statuses()
            .into_iter()
            .map(|(addr, _)| addr)
            .collect();

        for addr in addrs {
            let lb = Arc::clone(&lb);
            tokio::spawn(async move {
                match timeout(CONNECT_TIMEOUT, TcpStream::connect(&addr)).await {
                    Ok(Ok(_))  => lb.record_success(&addr),
                    Ok(Err(_)) | Err(_) => lb.record_failure(&addr),
                }
            });
        }
    }
}