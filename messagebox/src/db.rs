use std::fmt;
use std::path::Path;
use std::sync::Arc;

use redb::{Database, ReadableTable, TableDefinition};
use tracing::{debug, info};

/// Table: (mailbox_aid, seq_no) -> message_json_string
const MESSAGES: TableDefinition<(&str, u64), &str> = TableDefinition::new("messages");

/// Table: (mailbox_aid, digest) -> seq_no
const MESSAGE_INDEX: TableDefinition<(&str, &str), u64> = TableDefinition::new("message_index");

/// Table: mailbox_aid -> next_seq_no (counter)
const SEQUENCES: TableDefinition<&str, u64> = TableDefinition::new("sequences");

/// Table: digest_string -> response_string (for async query responses)
const RESPONSES: TableDefinition<&str, &str> = TableDefinition::new("responses");

/// Table: identifier -> firebase_token
const FIREBASE_TOKENS: TableDefinition<&str, &str> = TableDefinition::new("firebase_tokens");

/// Table: aid -> mailbox_metadata_json
const MAILBOXES: TableDefinition<&str, &str> = TableDefinition::new("mailboxes");

/// Table: aid -> acl_tokens_json (JSON array of hex-encoded HMAC tokens)
const ACL_TOKENS: TableDefinition<&str, &str> = TableDefinition::new("acl_tokens");

#[derive(Debug)]
pub struct DbError(Box<dyn std::error::Error + Send + Sync>);

impl fmt::Display for DbError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "database error: {}", self.0)
    }
}

impl std::error::Error for DbError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&*self.0)
    }
}

macro_rules! impl_from_db_error {
    ($($t:ty),+ $(,)?) => {
        $(
            impl From<$t> for DbError {
                fn from(e: $t) -> Self {
                    DbError(Box::new(e))
                }
            }
        )+
    };
}

impl_from_db_error!(
    redb::DatabaseError,
    redb::TableError,
    redb::CommitError,
    redb::StorageError,
    redb::TransactionError,
);

#[derive(Clone)]
pub struct Db {
    inner: Arc<Database>,
}

impl Db {
    pub fn open(path: &Path) -> Result<Self, DbError> {
        let db_path = path.join("mesagkesto.redb");
        info!(db_path = %db_path.display(), "Opening database");
        let db = Database::create(&db_path)?;
        let this = Self {
            inner: Arc::new(db),
        };
        this.init_tables()?;
        info!("Database initialized successfully");
        Ok(this)
    }

    fn init_tables(&self) -> Result<(), DbError> {
        debug!("Initializing database tables");
        let write_txn = self.inner.begin_write()?;
        write_txn.open_table(MESSAGES)?;
        write_txn.open_table(MESSAGE_INDEX)?;
        write_txn.open_table(SEQUENCES)?;
        write_txn.open_table(RESPONSES)?;
        write_txn.open_table(FIREBASE_TOKENS)?;
        write_txn.open_table(MAILBOXES)?;
        write_txn.open_table(ACL_TOKENS)?;
        write_txn.commit()?;
        debug!("Database tables initialized");
        Ok(())
    }

    // --- Messages ---

    pub fn save_message(&self, aid: &str, digest: &str, message: &str) -> Result<u64, DbError> {
        debug!(aid = %aid, digest = %digest, msg_len = message.len(), "Saving message to database");
        let write_txn = self.inner.begin_write()?;
        let seq = {
            let mut seq_table = write_txn.open_table(SEQUENCES)?;
            let current = seq_table.get(aid)?.map(|v| v.value()).unwrap_or(0);
            let next = current + 1;
            seq_table.insert(aid, next)?;

            let mut msg_table = write_txn.open_table(MESSAGES)?;
            msg_table.insert((aid, current), message)?;

            let mut idx_table = write_txn.open_table(MESSAGE_INDEX)?;
            idx_table.insert((aid, digest), current)?;

            current
        };
        write_txn.commit()?;
        debug!(aid = %aid, seq = seq, "Message saved to database");
        Ok(seq)
    }

    pub fn get_messages_by_sn(
        &self,
        aid: &str,
        from_seq: usize,
    ) -> Result<Option<(u64, Vec<String>)>, DbError> {
        let read_txn = self.inner.begin_read()?;
        let seq_table = read_txn.open_table(SEQUENCES)?;

        let total = match seq_table.get(aid)? {
            Some(v) => v.value(),
            None => return Ok(None),
        };
        if total == 0 {
            return Ok(None);
        }

        let last_seq = total - 1;
        let msg_table = read_txn.open_table(MESSAGES)?;
        let mut messages = Vec::new();

        for seq in (from_seq as u64)..total {
            if let Some(entry) = msg_table.get((aid, seq))? {
                messages.push(entry.value().to_string());
            }
        }

        if messages.is_empty() {
            Ok(None)
        } else {
            Ok(Some((last_seq, messages)))
        }
    }

    pub fn get_messages_by_digest(
        &self,
        aid: &str,
        digests: &[String],
    ) -> Result<Option<Vec<String>>, DbError> {
        let read_txn = self.inner.begin_read()?;
        let idx_table = read_txn.open_table(MESSAGE_INDEX)?;
        let msg_table = read_txn.open_table(MESSAGES)?;

        let mut results = Vec::new();
        for digest in digests {
            if let Some(seq_entry) = idx_table.get((aid, digest.as_str()))? {
                let seq = seq_entry.value();
                if let Some(msg_entry) = msg_table.get((aid, seq))? {
                    results.push(msg_entry.value().to_string());
                }
            }
        }

        if results.is_empty() {
            Ok(None)
        } else {
            Ok(Some(results))
        }
    }

    // --- Mailboxes ---

    pub fn save_mailbox(&self, aid: &str, metadata_json: &str) -> Result<(), DbError> {
        let write_txn = self.inner.begin_write()?;
        {
            let mut table = write_txn.open_table(MAILBOXES)?;
            table.insert(aid, metadata_json)?;
        }
        write_txn.commit()?;
        Ok(())
    }

    pub fn get_mailbox(&self, aid: &str) -> Result<Option<String>, DbError> {
        let read_txn = self.inner.begin_read()?;
        let table = read_txn.open_table(MAILBOXES)?;
        Ok(table.get(aid)?.map(|v| v.value().to_string()))
    }

    pub fn delete_mailbox(&self, aid: &str) -> Result<(), DbError> {
        let write_txn = self.inner.begin_write()?;
        {
            let mut table = write_txn.open_table(MAILBOXES)?;
            table.remove(aid)?;
        }
        write_txn.commit()?;
        Ok(())
    }

    // --- ACL Tokens ---

    pub fn save_acl_tokens(&self, aid: &str, tokens_json: &str) -> Result<(), DbError> {
        let write_txn = self.inner.begin_write()?;
        {
            let mut table = write_txn.open_table(ACL_TOKENS)?;
            table.insert(aid, tokens_json)?;
        }
        write_txn.commit()?;
        Ok(())
    }

    pub fn get_acl_tokens(&self, aid: &str) -> Result<Option<String>, DbError> {
        let read_txn = self.inner.begin_read()?;
        let table = read_txn.open_table(ACL_TOKENS)?;
        Ok(table.get(aid)?.map(|v| v.value().to_string()))
    }

    // --- Responses ---

    pub fn save_response(&self, digest: &str, response: &str) -> Result<(), DbError> {
        let write_txn = self.inner.begin_write()?;
        {
            let mut table = write_txn.open_table(RESPONSES)?;
            table.insert(digest, response)?;
        }
        write_txn.commit()?;
        Ok(())
    }

    pub fn get_response(&self, digest: &str) -> Result<Option<String>, DbError> {
        let read_txn = self.inner.begin_read()?;
        let table = read_txn.open_table(RESPONSES)?;
        Ok(table.get(digest)?.map(|v| v.value().to_string()))
    }

    // --- Firebase Tokens ---

    pub fn save_firebase_token(&self, identifier: &str, token: &str) -> Result<(), DbError> {
        let write_txn = self.inner.begin_write()?;
        {
            let mut table = write_txn.open_table(FIREBASE_TOKENS)?;
            table.insert(identifier, token)?;
        }
        write_txn.commit()?;
        Ok(())
    }

    pub fn get_firebase_token(&self, identifier: &str) -> Result<Option<String>, DbError> {
        let read_txn = self.inner.begin_read()?;
        let table = read_txn.open_table(FIREBASE_TOKENS)?;
        Ok(table.get(identifier)?.map(|v| v.value().to_string()))
    }

    // --- Generic helpers for additional tables ---

    pub fn ensure_table(&self, table_def: TableDefinition<&str, &str>) -> Result<(), DbError> {
        let write_txn = self.inner.begin_write()?;
        write_txn.open_table(table_def)?;
        write_txn.commit()?;
        Ok(())
    }

    pub fn put(
        &self,
        table_def: TableDefinition<&str, &str>,
        key: &str,
        value: &str,
    ) -> Result<(), DbError> {
        let write_txn = self.inner.begin_write()?;
        {
            let mut table = write_txn.open_table(table_def)?;
            table.insert(key, value)?;
        }
        write_txn.commit()?;
        Ok(())
    }

    pub fn get(
        &self,
        table_def: TableDefinition<&str, &str>,
        key: &str,
    ) -> Result<Option<String>, DbError> {
        let read_txn = self.inner.begin_read()?;
        let table = read_txn.open_table(table_def)?;
        Ok(table.get(key)?.map(|v| v.value().to_string()))
    }

    pub fn delete(&self, table_def: TableDefinition<&str, &str>, key: &str) -> Result<(), DbError> {
        let write_txn = self.inner.begin_write()?;
        {
            let mut table = write_txn.open_table(table_def)?;
            table.remove(key)?;
        }
        write_txn.commit()?;
        Ok(())
    }
}
