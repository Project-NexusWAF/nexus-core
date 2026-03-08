use chrono::{DateTime, Utc};
use sqlx::PgPool;

pub struct RulesStore {
  pool: PgPool,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct RuleSetMeta {
  pub id: i32,
  pub version: String,
  pub created_at: DateTime<Utc>,
  pub active: bool,
}

impl RulesStore {
  pub fn new(pool: PgPool) -> Self {
    Self { pool }
  }

  pub async fn load_active(&self) -> Result<Option<String>, sqlx::Error> {
    sqlx::query_scalar::<_, String>(
      "SELECT content FROM rule_sets WHERE active = TRUE ORDER BY created_at DESC LIMIT 1",
    )
    .fetch_optional(&self.pool)
    .await
  }

  pub async fn save(&self, version: &str, content: &str) -> Result<(), sqlx::Error> {
    let mut tx = self.pool.begin().await?;

    sqlx::query("UPDATE rule_sets SET active = FALSE WHERE active = TRUE")
      .execute(&mut *tx)
      .await?;

    sqlx::query(
      "INSERT INTO rule_sets (version, content, active) VALUES ($1, $2, TRUE)
       ON CONFLICT (version) DO UPDATE SET content = EXCLUDED.content, active = TRUE",
    )
    .bind(version)
    .bind(content)
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;
    tracing::info!(version = version, "Rule set saved and activated");
    Ok(())
  }

  pub async fn list_versions(&self) -> Result<Vec<RuleSetMeta>, sqlx::Error> {
    sqlx::query_as::<_, RuleSetMeta>(
      "SELECT id, version, created_at, active FROM rule_sets ORDER BY created_at DESC",
    )
    .fetch_all(&self.pool)
    .await
  }
}
