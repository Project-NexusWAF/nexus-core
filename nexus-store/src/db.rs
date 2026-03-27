use nexus_config::StoreConfig;
use sqlx::PgPool;

pub struct StorePool {
  pub pg: PgPool,
  pub config: StoreConfig,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct AttackLogCounters {
  pub requests_total: u64,
  pub blocked_total: u64,
  pub rate_limited_total: u64,
}

#[derive(sqlx::FromRow)]
struct AttackLogCountersRow {
  requests_total: i64,
  blocked_total: i64,
  rate_limited_total: i64,
}

impl StorePool {
  pub async fn connect(cfg: &StoreConfig) -> Result<Self, sqlx::Error> {
    let pg = PgPool::connect(&cfg.postgres_url).await?;

    sqlx::raw_sql(include_str!("migrations/001_init.sql"))
      .execute(&pg)
      .await?;

    tracing::info!("PostgreSQL connected and migrations applied");
    Ok(Self {
      pg,
      config: cfg.clone(),
    })
  }

  pub fn rules(&self) -> crate::rules_store::RulesStore {
    crate::rules_store::RulesStore::new(self.pg.clone())
  }

  pub async fn attack_log_counters(&self) -> Result<AttackLogCounters, sqlx::Error> {
    let row = sqlx::query_as::<_, AttackLogCountersRow>(
      "SELECT \
         COUNT(*)::bigint AS requests_total, \
         COUNT(*) FILTER (WHERE decision = 'Block')::bigint AS blocked_total, \
         COUNT(*) FILTER (WHERE decision = 'RateLimit')::bigint AS rate_limited_total \
       FROM attack_logs",
    )
    .fetch_one(&self.pg)
    .await?;

    Ok(AttackLogCounters {
      requests_total: row.requests_total.max(0) as u64,
      blocked_total: row.blocked_total.max(0) as u64,
      rate_limited_total: row.rate_limited_total.max(0) as u64,
    })
  }
}
