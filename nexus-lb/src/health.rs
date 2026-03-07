use std::{sync::Arc, time::Duration};
use tokio::{net::TcpStream, time};
use crate::balancer::LoadBalancer;

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
                match TcpStream::connect(&addr).await {
                    Ok(_)  => lb.record_success(&addr),
                    Err(_) => lb.record_failure(&addr),
                }
            });
        }
    }
}