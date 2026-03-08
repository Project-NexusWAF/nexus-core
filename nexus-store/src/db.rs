use nexus_config::StoreConfig;
use sqlx::PgPool;

pub struct StorePool {
  pub pg: PgPool,
  pub config: StoreConfig,
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
}
