use blocker_core::{normalize_domain, BlockAction, BlockEvent};
use rusqlite::{params, Connection, OptionalExtension};
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Debug)]
pub struct BlockerDb {
    conn: Connection,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredBlockEvent {
    pub id: i64,
    pub domain: String,
    pub action: String,
    pub matched_rule: Option<String>,
    pub rule_source: Option<String>,
    pub category: Option<String>,
    pub occurred_at_unix: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockedDomainSummary {
    pub domain: String,
    pub block_count: i64,
    pub last_blocked_at_unix: i64,
    pub matched_rule: Option<String>,
    pub rule_source: Option<String>,
    pub category: Option<String>,
}

impl BlockerDb {
    pub fn open(path: impl AsRef<Path>) -> rusqlite::Result<Self> {
        let conn = Connection::open(path)?;
        let db = Self { conn };
        db.migrate()?;
        Ok(db)
    }

    pub fn open_in_memory() -> rusqlite::Result<Self> {
        let conn = Connection::open_in_memory()?;
        let db = Self { conn };
        db.migrate()?;
        Ok(db)
    }

    fn migrate(&self) -> rusqlite::Result<()> {
        self.conn.execute_batch(
            r#"
            PRAGMA foreign_keys = ON;
            
            CREATE TABLE IF NOT EXISTS blocked_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT NOT NULL,
                action TEXT NOT NULL,
                matched_rule TEXT,
                rule_source TEXT,
                category TEXT,
                occurred_at_unix INTEGER NOT NULL
            );
        
            CREATE INDEX IF NOT EXISTS idx_blocked_events_occurred_at
                ON blocked_events (occurred_at_unix DESC);
                
            CREATE INDEX IF NOT EXISTS idx_blocked_events_domain
                ON blocked_events (domain);

            CREATE TABLE IF NOT EXISTS allowlist (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT NOT NULL UNIQUE,
                created_at_unix INTEGER NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_allowlist_domain
                ON allowlist (domain);

            CREATE TABLE IF NOT EXISTS blocklist (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT NOT NULL UNIQUE,
                created_at_unix INTEGER NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_blocklist_domain
                ON blocklist (domain);

            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );

            "#,
        )?;

        Ok(())
    }

    pub fn record_event(&self, event: &BlockEvent) -> rusqlite::Result<i64> {
        let occurred_at_unix = system_time_to_unix_seconds(event.occurred_at);

        self.conn.execute(
            r#"
            INSERT INTO blocked_events (
                domain,
                action,
                matched_rule,
                rule_source,
                category,
                occurred_at_unix
            )
            VALUES (?1, ?2, ?3, ?4, ?5, ?6)
            "#,
            params![
                event.domain,
                action_to_text(&event.action),
                event.matched_rule,
                event.rule_source,
                event.category,
                occurred_at_unix
            ],
        )?;

        Ok(self.conn.last_insert_rowid())
    }

    pub fn recent_events(&self, limit: i64) -> rusqlite::Result<Vec<StoredBlockEvent>> {
        let safe_limit = limit.clamp(1, 500);

        let mut statement = self.conn.prepare(
            r#"
            SELECT
                id, 
                domain,
                action,
                matched_rule,
                rule_source,
                category,
                occurred_at_unix
            FROM blocked_events
            ORDER BY occurred_at_unix DESC, id DESC
            LIMIT ?1
            "#,
        )?;

        let rows = statement.query_map(params![safe_limit], |row| {
            Ok(StoredBlockEvent {
                id: row.get(0)?,
                domain: row.get(1)?,
                action: row.get(2)?,
                matched_rule: row.get(3)?,
                rule_source: row.get(4)?,
                category: row.get(5)?,
                occurred_at_unix: row.get(6)?,
            })
        })?;

        rows.collect()
    }

    pub fn blocked_domain_summaries(
        &self,
        limit: i64,
    ) -> rusqlite::Result<Vec<BlockedDomainSummary>> {
        let safe_limit = limit.clamp(1, 500);

        let mut statement = self.conn.prepare(
            r#"
            SELECT
                grouped.domain,
                grouped.block_count,
                grouped.last_blocked_at_unix,
                latest.matched_rule,
                latest.rule_source,
                latest.category
            FROM (
                SELECT
                    domain,
                    COUNT(*) AS block_count,
                    MAX(occurred_at_unix) AS last_blocked_at_unix
                FROM blocked_events
                WHERE action = 'blocked'
                GROUP BY domain
            ) grouped
            LEFT JOIN blocked_events latest
                ON latest.id = (
                    SELECT id
                    FROM blocked_events
                    WHERE action = 'blocked'
                    AND domain = grouped.domain
                    ORDER BY occurred_at_unix DESC, id DESC
                    LIMIT 1
                )
            ORDER BY grouped.last_blocked_at_unix DESC, grouped.domain ASC
            LIMIT ?1
            "#,
        )?;

        let rows = statement.query_map(params![safe_limit], |row| {
            Ok(BlockedDomainSummary {
                domain: row.get(0)?,
                block_count: row.get(1)?,
                last_blocked_at_unix: row.get(2)?,
                matched_rule: row.get(3)?,
                rule_source: row.get(4)?,
                category: row.get(5)?,
            })
        })?;

        rows.collect()
    }

    pub fn add_allow_domain(&self, domain: &str) -> rusqlite::Result<bool> {
        let domain = normalize_domain(domain).map_err(to_sql_error)?;
        let now = current_unix_seconds();

        self.conn.execute(
            r#"
            INSERT OR IGNORE INTO allowlist (domain, created_at_unix)
            Values(?1, ?2)
            "#,
            params![domain, now],
        )?;

        Ok(self.conn.changes()> 0)
    }

    pub fn remove_allow_domain(&self, domain: &str) -> rusqlite::Result<bool> {
        let domain = normalize_domain(domain).map_err(to_sql_error)?;

        self.conn.execute(
            r#"
            DELETE FROM allowlist
            WHERE domain = ?1
            "#,
            params![domain],
        )?;

        Ok(self.conn.changes() > 0)
    }

    pub fn is_exact_domain_allowed(&self, domain: &str) -> rusqlite::Result<bool> {
        let domain = normalize_domain(domain).map_err(to_sql_error)?;

        let exists = self
            .conn
            .query_row(
                r#"
                SELECT 1
                FROM allowlist
                WHERE domain = ?1
                LIMIT 1
                "#,
                params![domain],
                |_| Ok(()),
            )
            .optional()?
            .is_some();

        Ok(exists)
    }

    pub fn list_allow_domains(&self) -> rusqlite::Result<Vec<String>> {
        let mut statement = self.conn.prepare(
            r#"
            SELECt domain
            FROM allowlist
            ORDER BY domain ASC
            "#,
        )?;

        let rows = statement.query_map([], |row| row.get::<_, String>(0))?;

        rows.collect()
    }

    pub fn add_block_domain(&self, domain: &str) -> rusqlite::Result<bool> {
        let changed = self.conn.execute(
            r#"
            INSERT OR IGNORE INTO blocklist (domain, created_at_unix)
            VALUES (?1, ?2)
            "#,
            params![domain, current_unix_seconds()],
        )?;

        Ok(changed > 0)
    }

    pub fn remove_block_domain(&self, domain: &str) -> rusqlite::Result<bool> {
        let domain = normalize_domain(domain).map_err(to_sql_error)?;

        self.conn.execute(
            r#"
            DELETE FROM blocklist
            WHERE domain = ?1
            "#,
            params![domain],
        )?;

        Ok(self.conn.changes() > 0)
    }

    pub fn is_exact_domain_blocked(&self, domain: &str) -> rusqlite::Result<bool> {
        let domain = normalize_domain(domain).map_err(to_sql_error)?;

        let exists = self
            .conn
            .query_row(
                r#"
                SELECT 1
                FROM blocklist
                WHERE domain = ?1
                LIMIT 1
                "#,
                params![domain],
                |_| Ok(()),
            )
            .optional()?
            .is_some();

        Ok(exists)
    }

    pub fn list_block_domains(&self) -> rusqlite::Result<Vec<String>> {
        let mut statement = self.conn.prepare(
            r#"
            SELECT domain
            FROM blocklist
            ORDER BY domain ASC
            "#,
        )?;

        let rows = statement.query_map([], |row| row.get::<_, String>(0))?;

        rows.collect()
    }

    pub fn set_setting(&self, key: &str, value: &str) -> rusqlite::Result<()> {
        self.conn.execute(
            r#"
            INSERT INTO settings (key, value)
            VALUES (?1, ?2)
            ON CONFLICT(key) DO UPDATE SET value = excluded.value
            "#,
            params![key, value],
        )?;

        Ok(())
    }

    pub fn get_setting(&self, key: &str) -> rusqlite::Result<Option<String>> {
        self.conn
            .query_row(
                r#"
                SELECT value
                FROM settings
                WHERE key = ?1
                LIMIT 1
                "#,
                params![key],
                |row| row.get::<_, String>(0),
            )
            .optional()
    }

    pub fn set_protection_enabled(&self, enabled: bool) -> rusqlite::Result<()> {
        let value = if enabled { "true" } else { "false" };
        self.set_setting("protection_enabled", value)
    }

    pub fn is_protection_enabled(&self) -> rusqlite::Result<bool> {
        let value = self.get_setting("protection_enabled")?;

        Ok(value.as_deref() != Some("false"))
    }
}

fn action_to_text(action: &BlockAction) -> &'static str {
    match action {
        BlockAction::Blocked => "blocked",
        BlockAction::AllowedByUserRule => "allowed_by_user_rule",
        BlockAction::AllowedByDefault => "allowed_by_default",
    }
}

fn system_time_to_unix_seconds(time: SystemTime) -> i64 {
    time.duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs() as i64
}

fn current_unix_seconds() -> i64 {
    system_time_to_unix_seconds(SystemTime::now())
}

fn to_sql_error(error: blocker_core::BlockerError) -> rusqlite::Error {
    rusqlite::Error::ToSqlConversionFailure(Box::new(error))
}

#[cfg(test)]
mod tests {
    use super::*;
    use blocker_core::BlockerEngine;

    #[test]
    fn records_and_reads_recent_blocked_events() {
        let db = BlockerDb::open_in_memory().unwrap();

        let mut engine = BlockerEngine::new();
        engine
            .add_block_rule("ads.example.com", Some("test"), Some("ad"))
            .unwrap();

        let event = engine.check_domain_with_event("ads.example.com").unwrap();
        let id = db.record_event(&event).unwrap();

        assert!(id > 0);

        let events = db.recent_events(10).unwrap();

        assert_eq!(events.len(), 1);
        assert_eq!(events[0].domain, "ads.example.com");
        assert_eq!(events[0].action, "blocked");
        assert_eq!(events[0].matched_rule.as_deref(), Some("ads.example.com"));
        assert_eq!(events[0].rule_source.as_deref(), Some("test"));
        assert_eq!(events[0].category.as_deref(), Some("ad"));
    }

    #[test]
    fn stores_allowlist_domains() {
        let db = BlockerDb::open_in_memory().unwrap();

        let added = db.add_allow_domain("Safe.Example.Com.").unwrap();
        let duplicate = db.add_allow_domain("safe.example.com").unwrap();

        assert!(added);
        assert!(!duplicate);

        assert!(db.is_exact_domain_allowed("safe.example.com").unwrap());

        let domains = db.list_allow_domains().unwrap();
        assert_eq!(domains, vec!["safe.example.com"]);
    }

    #[test]
    fn removes_allowlist_domains() {
        let db = BlockerDb::open_in_memory().unwrap();

        db.add_allow_domain("safe.example.com").unwrap();

        assert!(db.remove_allow_domain("safe.example.com").unwrap());
        assert!(!db.is_exact_domain_allowed("safe.example.com").unwrap());

        assert!(!db.remove_allow_domain("safe.example.com").unwrap());
    }

    #[test]
    fn recent_events_limit_is_clamped() {
        let db = BlockerDb::open_in_memory().unwrap();

        let mut engine = BlockerEngine::new();
        engine
            .add_block_rule("ads.example.com", Some("test"), Some("ad"))
            .unwrap();

        let event = engine.check_domain_with_event("ads.example.com").unwrap();

        for _ in 0..3 {
            db.record_event(&event).unwrap();
        }

        let events = db.recent_events(2).unwrap();

        assert_eq!(events.len(), 2);
    }

    #[test]
    fn protection_is_enabled_by_default_and_can_be_changed() {
        let db = BlockerDb::open_in_memory().unwrap();

        assert!(db.is_protection_enabled().unwrap());

        db.set_protection_enabled(false).unwrap();
        assert!(!db.is_protection_enabled().unwrap());

        db.set_protection_enabled(true).unwrap();
        assert!(db.is_protection_enabled().unwrap());
    }

    #[test]
    fn summarizes_blocked_domains_by_domain() {
        let db = BlockerDb::open_in_memory().unwrap();

        let mut engine = BlockerEngine::new();
        engine
            .add_block_rule("ads.example.com", Some("test"), Some("ad"))
            .unwrap();

        let event = engine.check_domain_with_event("ads.example.com").unwrap();

        db.record_event(&event).unwrap();
        db.record_event(&event).unwrap();
        db.record_event(&event).unwrap();

        let summaries = db.blocked_domain_summaries(10).unwrap();

        assert_eq!(summaries.len(), 1);
        assert_eq!(summaries[0].domain, "ads.example.com");
        assert_eq!(summaries[0].block_count, 3);
        assert_eq!(summaries[0].matched_rule.as_deref(), Some("ads.example.com"));
        assert_eq!(summaries[0].rule_source.as_deref(), Some("test"));
        assert_eq!(summaries[0].category.as_deref(), Some("ad"));
    }

    #[test]
    fn stores_blocklist_domains() {
        let db = BlockerDb::open_in_memory().unwrap();

        assert!(db.add_block_domain("ads.example.com").unwrap());
        assert!(!db.add_block_domain("ads.example.com").unwrap());

        assert!(db.is_exact_domain_blocked("ads.example.com").unwrap());
        assert!(!db.is_exact_domain_blocked("normal.example.com").unwrap());

        let domains = db.list_block_domains().unwrap();

        assert_eq!(domains, vec!["ads.example.com"]);
    }

    #[test]
    fn removes_blocklist_domains() {
        let db = BlockerDb::open_in_memory().unwrap();

        db.add_block_domain("ads.example.com").unwrap();

        assert!(db.remove_block_domain("ads.example.com").unwrap());
        assert!(!db.remove_block_domain("ads.example.com").unwrap());

        assert!(!db.is_exact_domain_blocked("ads.example.com").unwrap());
    }
}