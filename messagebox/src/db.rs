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

// --- Channel tables ---

/// Table: channel_said -> channel_metadata_json
const CHANNELS: TableDefinition<&str, &str> = TableDefinition::new("channels");

/// Table: (channel_said, seq_no) -> message_json_string
const CHANNEL_MESSAGES: TableDefinition<(&str, u64), &str> = TableDefinition::new("channel_messages");

/// Table: (channel_said, digest) -> seq_no
const CHANNEL_MESSAGE_INDEX: TableDefinition<(&str, &str), u64> =
    TableDefinition::new("channel_message_index");

/// Table: channel_said -> next_seq_no (counter)
const CHANNEL_SEQUENCES: TableDefinition<&str, u64> = TableDefinition::new("channel_sequences");

/// Table: (owner_aid, topic_name) -> channel_said (broadcast discovery index)
const BROADCAST_INDEX: TableDefinition<(&str, &str), &str> =
    TableDefinition::new("broadcast_index");

/// Table: (invited_aid, channel_said) -> invite_json
const CHANNEL_INVITES: TableDefinition<(&str, &str), &str> =
    TableDefinition::new("channel_invites");

// --- Formal Mail tables ---

/// Table: (recipient_aid, seq_no) -> mail_envelope_json
const MAIL_MESSAGES: TableDefinition<(&str, u64), &str> = TableDefinition::new("mail_messages");

/// Table: recipient_aid -> next_seq_no (counter)
const MAIL_SEQUENCES: TableDefinition<&str, u64> = TableDefinition::new("mail_sequences");

/// Table: (sender_aid, message_id) -> receipt_json
const MAIL_RECEIPTS: TableDefinition<(&str, &str), &str> = TableDefinition::new("mail_receipts");

/// Table: said (content hash) -> blob (bytes)
const VAULT_BLOBS: TableDefinition<&str, &[u8]> = TableDefinition::new("vault_blobs");

// --- Registration tables ---

/// Table: invite_token_hex -> invite_metadata_json
const INVITE_TOKENS: TableDefinition<&str, &str> = TableDefinition::new("invite_tokens");

/// Table: aid -> "1" (presence table)
const AID_WHITELIST: TableDefinition<&str, &str> = TableDefinition::new("aid_whitelist");

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
        write_txn.open_table(CHANNELS)?;
        write_txn.open_table(CHANNEL_MESSAGES)?;
        write_txn.open_table(CHANNEL_MESSAGE_INDEX)?;
        write_txn.open_table(CHANNEL_SEQUENCES)?;
        write_txn.open_table(BROADCAST_INDEX)?;
        write_txn.open_table(CHANNEL_INVITES)?;
        write_txn.open_table(MAIL_MESSAGES)?;
        write_txn.open_table(MAIL_SEQUENCES)?;
        write_txn.open_table(MAIL_RECEIPTS)?;
        write_txn.open_table(VAULT_BLOBS)?;
        write_txn.open_table(INVITE_TOKENS)?;
        write_txn.open_table(AID_WHITELIST)?;
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

    // --- Channels ---

    pub fn save_channel(&self, said: &str, metadata_json: &str) -> Result<(), DbError> {
        let write_txn = self.inner.begin_write()?;
        {
            let mut table = write_txn.open_table(CHANNELS)?;
            table.insert(said, metadata_json)?;
        }
        write_txn.commit()?;
        Ok(())
    }

    pub fn get_channel(&self, said: &str) -> Result<Option<String>, DbError> {
        let read_txn = self.inner.begin_read()?;
        let table = read_txn.open_table(CHANNELS)?;
        Ok(table.get(said)?.map(|v| v.value().to_string()))
    }

    pub fn delete_channel(&self, said: &str) -> Result<(), DbError> {
        let write_txn = self.inner.begin_write()?;
        {
            let mut table = write_txn.open_table(CHANNELS)?;
            table.remove(said)?;
        }
        write_txn.commit()?;
        Ok(())
    }

    /// Scan all channels and return those where the given AID is a member.
    /// Returns Vec of (channel_said, metadata_json).
    pub fn list_channels_for_aid(&self, aid: &str) -> Result<Vec<(String, String)>, DbError> {
        let read_txn = self.inner.begin_read()?;
        let table = read_txn.open_table(CHANNELS)?;
        let mut results = Vec::new();
        for entry in table.iter()? {
            let (key, value) = entry?;
            let metadata = value.value().to_string();
            // Check membership by looking for the AID in the JSON
            if metadata.contains(aid) {
                results.push((key.value().to_string(), metadata));
            }
        }
        Ok(results)
    }

    /// List all channels on this instance. Returns Vec of (channel_said, metadata_json).
    pub fn list_all_channels(&self) -> Result<Vec<(String, String)>, DbError> {
        let read_txn = self.inner.begin_read()?;
        let table = read_txn.open_table(CHANNELS)?;
        let mut results = Vec::new();
        for entry in table.iter()? {
            let (key, value) = entry?;
            results.push((key.value().to_string(), value.value().to_string()));
        }
        Ok(results)
    }

    // --- Channel Messages ---

    pub fn save_channel_message(
        &self,
        channel_said: &str,
        digest: &str,
        message: &str,
    ) -> Result<u64, DbError> {
        debug!(channel = %channel_said, digest = %digest, msg_len = message.len(), "Saving channel message");
        let write_txn = self.inner.begin_write()?;
        let seq = {
            let mut seq_table = write_txn.open_table(CHANNEL_SEQUENCES)?;
            let current = seq_table
                .get(channel_said)?
                .map(|v| v.value())
                .unwrap_or(0);
            let next = current + 1;
            seq_table.insert(channel_said, next)?;

            let mut msg_table = write_txn.open_table(CHANNEL_MESSAGES)?;
            msg_table.insert((channel_said, current), message)?;

            let mut idx_table = write_txn.open_table(CHANNEL_MESSAGE_INDEX)?;
            idx_table.insert((channel_said, digest), current)?;

            current
        };
        write_txn.commit()?;
        debug!(channel = %channel_said, seq = seq, "Channel message saved");
        Ok(seq)
    }

    pub fn get_channel_messages_by_sn(
        &self,
        channel_said: &str,
        from_seq: usize,
    ) -> Result<Option<(u64, Vec<String>)>, DbError> {
        let read_txn = self.inner.begin_read()?;
        let seq_table = read_txn.open_table(CHANNEL_SEQUENCES)?;

        let total = match seq_table.get(channel_said)? {
            Some(v) => v.value(),
            None => return Ok(None),
        };
        if total == 0 {
            return Ok(None);
        }

        let last_seq = total - 1;
        let msg_table = read_txn.open_table(CHANNEL_MESSAGES)?;
        let mut messages = Vec::new();

        for seq in (from_seq as u64)..total {
            if let Some(entry) = msg_table.get((channel_said, seq))? {
                messages.push(entry.value().to_string());
            }
        }

        if messages.is_empty() {
            Ok(None)
        } else {
            Ok(Some((last_seq, messages)))
        }
    }

    pub fn get_channel_messages_by_digest(
        &self,
        channel_said: &str,
        digests: &[String],
    ) -> Result<Option<Vec<String>>, DbError> {
        let read_txn = self.inner.begin_read()?;
        let idx_table = read_txn.open_table(CHANNEL_MESSAGE_INDEX)?;
        let msg_table = read_txn.open_table(CHANNEL_MESSAGES)?;

        let mut results = Vec::new();
        for digest in digests {
            if let Some(seq_entry) = idx_table.get((channel_said, digest.as_str()))? {
                let seq = seq_entry.value();
                if let Some(msg_entry) = msg_table.get((channel_said, seq))? {
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

    // --- Broadcast Index ---

    pub fn save_broadcast_index(
        &self,
        owner_aid: &str,
        topic: &str,
        channel_said: &str,
    ) -> Result<(), DbError> {
        let write_txn = self.inner.begin_write()?;
        {
            let mut table = write_txn.open_table(BROADCAST_INDEX)?;
            table.insert((owner_aid, topic), channel_said)?;
        }
        write_txn.commit()?;
        Ok(())
    }

    pub fn get_broadcast_by_topic(
        &self,
        owner_aid: &str,
        topic: &str,
    ) -> Result<Option<String>, DbError> {
        let read_txn = self.inner.begin_read()?;
        let table = read_txn.open_table(BROADCAST_INDEX)?;
        Ok(table
            .get((owner_aid, topic))?
            .map(|v| v.value().to_string()))
    }

    pub fn delete_broadcast_index(&self, owner_aid: &str, topic: &str) -> Result<(), DbError> {
        let write_txn = self.inner.begin_write()?;
        {
            let mut table = write_txn.open_table(BROADCAST_INDEX)?;
            table.remove((owner_aid, topic))?;
        }
        write_txn.commit()?;
        Ok(())
    }

    // --- Channel Invites ---

    pub fn save_invite(
        &self,
        invited_aid: &str,
        channel_said: &str,
        invite_json: &str,
    ) -> Result<(), DbError> {
        let write_txn = self.inner.begin_write()?;
        {
            let mut table = write_txn.open_table(CHANNEL_INVITES)?;
            table.insert((invited_aid, channel_said), invite_json)?;
        }
        write_txn.commit()?;
        Ok(())
    }

    /// Get all pending invites for an AID. Returns Vec of (channel_said, invite_json).
    pub fn get_pending_invites(&self, invited_aid: &str) -> Result<Vec<(String, String)>, DbError> {
        let read_txn = self.inner.begin_read()?;
        let table = read_txn.open_table(CHANNEL_INVITES)?;
        let mut results = Vec::new();

        // Scan range: all entries where first key component is invited_aid
        let range_start = (invited_aid, "");
        let range_end = (invited_aid, "\x7f"); // ASCII DEL, sorts after all printable chars
        for entry in table.range(range_start..range_end)? {
            let (key, value) = entry?;
            let (_, channel_said) = key.value();
            results.push((channel_said.to_string(), value.value().to_string()));
        }

        Ok(results)
    }

    pub fn delete_invite(&self, invited_aid: &str, channel_said: &str) -> Result<(), DbError> {
        let write_txn = self.inner.begin_write()?;
        {
            let mut table = write_txn.open_table(CHANNEL_INVITES)?;
            table.remove((invited_aid, channel_said))?;
        }
        write_txn.commit()?;
        Ok(())
    }

    /// Atomic channel creation: saves channel metadata, broadcast index (if applicable), and invites in one transaction.
    pub fn save_channel_with_invites(
        &self,
        said: &str,
        metadata_json: &str,
        broadcast_index: Option<(&str, &str)>, // (owner_aid, topic_name)
        invites: &[(&str, &str)],              // (invited_aid, invite_json)
    ) -> Result<(), DbError> {
        let write_txn = self.inner.begin_write()?;
        {
            let mut channels = write_txn.open_table(CHANNELS)?;
            channels.insert(said, metadata_json)?;

            if let Some((owner_aid, topic)) = broadcast_index {
                let mut idx = write_txn.open_table(BROADCAST_INDEX)?;
                idx.insert((owner_aid, topic), said)?;
            }

            if !invites.is_empty() {
                let mut inv_table = write_txn.open_table(CHANNEL_INVITES)?;
                for (invited_aid, invite_json) in invites {
                    inv_table.insert((*invited_aid, said), *invite_json)?;
                }
            }
        }
        write_txn.commit()?;
        Ok(())
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

    // --- Formal Mail ---

    /// Store an incoming mail envelope for a recipient. Returns the sequence number.
    pub fn save_mail_message(&self, recipient_aid: &str, envelope_json: &str) -> Result<u64, DbError> {
        debug!(aid = %recipient_aid, "Saving mail message");
        let write_txn = self.inner.begin_write()?;
        let seq;
        {
            // Get and increment sequence number
            let mut seq_table = write_txn.open_table(MAIL_SEQUENCES)?;
            let current = seq_table
                .get(recipient_aid)?
                .map(|v| v.value())
                .unwrap_or(0);
            seq = current;
            seq_table.insert(recipient_aid, current + 1)?;

            // Store the envelope
            let mut msg_table = write_txn.open_table(MAIL_MESSAGES)?;
            msg_table.insert((recipient_aid, seq), envelope_json)?;
        }
        write_txn.commit()?;
        info!(aid = %recipient_aid, seq = seq, "Mail message stored");
        Ok(seq)
    }

    /// Retrieve pending mail messages for a recipient, starting from `from_seq`.
    pub fn get_mail_messages(&self, recipient_aid: &str, from_seq: u64) -> Result<Vec<(u64, String)>, DbError> {
        let read_txn = self.inner.begin_read()?;
        let table = read_txn.open_table(MAIL_MESSAGES)?;
        let mut results = Vec::new();

        // Iterate from from_seq up to current max
        let max_seq = {
            let seq_table = read_txn.open_table(MAIL_SEQUENCES)?;
            seq_table.get(recipient_aid)?.map(|v| v.value()).unwrap_or(0)
        };

        for seq in from_seq..max_seq {
            if let Some(entry) = table.get((recipient_aid, seq))? {
                results.push((seq, entry.value().to_string()));
            }
        }
        Ok(results)
    }

    /// Delete a specific mail message (after client acknowledges receipt).
    pub fn delete_mail_message(&self, recipient_aid: &str, seq: u64) -> Result<(), DbError> {
        let write_txn = self.inner.begin_write()?;
        {
            let mut table = write_txn.open_table(MAIL_MESSAGES)?;
            table.remove((recipient_aid, seq))?;
        }
        write_txn.commit()?;
        Ok(())
    }

    /// Store a mail receipt (delivery or read) for a sender to retrieve.
    pub fn save_mail_receipt(&self, sender_aid: &str, message_id: &str, receipt_json: &str) -> Result<(), DbError> {
        debug!(sender = %sender_aid, msg_id = %message_id, "Saving mail receipt");
        let write_txn = self.inner.begin_write()?;
        {
            let mut table = write_txn.open_table(MAIL_RECEIPTS)?;
            table.insert((sender_aid, message_id), receipt_json)?;
        }
        write_txn.commit()?;
        Ok(())
    }

    /// Get a mail receipt for a specific message.
    pub fn get_mail_receipt(&self, sender_aid: &str, message_id: &str) -> Result<Option<String>, DbError> {
        let read_txn = self.inner.begin_read()?;
        let table = read_txn.open_table(MAIL_RECEIPTS)?;
        Ok(table.get((sender_aid, message_id))?.map(|v| v.value().to_string()))
    }

    // --- Storage Vault ---

    /// Store a content-addressed blob in the vault.
    pub fn vault_put(&self, said: &str, data: &[u8]) -> Result<(), DbError> {
        debug!(said = %said, size = data.len(), "Storing vault blob");
        let write_txn = self.inner.begin_write()?;
        {
            let mut table = write_txn.open_table(VAULT_BLOBS)?;
            table.insert(said, data)?;
        }
        write_txn.commit()?;
        info!(said = %said, "Vault blob stored");
        Ok(())
    }

    /// Retrieve a blob from the vault by SAID.
    pub fn vault_get(&self, said: &str) -> Result<Option<Vec<u8>>, DbError> {
        let read_txn = self.inner.begin_read()?;
        let table = read_txn.open_table(VAULT_BLOBS)?;
        Ok(table.get(said)?.map(|v| v.value().to_vec()))
    }

    /// Check if a blob exists in the vault.
    pub fn vault_exists(&self, said: &str) -> Result<bool, DbError> {
        let read_txn = self.inner.begin_read()?;
        let table = read_txn.open_table(VAULT_BLOBS)?;
        Ok(table.get(said)?.is_some())
    }

    // --- Registration: Invite Tokens ---

    pub fn save_invite_token(&self, token: &str, metadata_json: &str) -> Result<(), DbError> {
        let write_txn = self.inner.begin_write()?;
        {
            let mut table = write_txn.open_table(INVITE_TOKENS)?;
            table.insert(token, metadata_json)?;
        }
        write_txn.commit()?;
        Ok(())
    }

    pub fn get_invite_token(&self, token: &str) -> Result<Option<String>, DbError> {
        let read_txn = self.inner.begin_read()?;
        let table = read_txn.open_table(INVITE_TOKENS)?;
        Ok(table.get(token)?.map(|v| v.value().to_string()))
    }

    pub fn delete_invite_token(&self, token: &str) -> Result<(), DbError> {
        let write_txn = self.inner.begin_write()?;
        {
            let mut table = write_txn.open_table(INVITE_TOKENS)?;
            table.remove(token)?;
        }
        write_txn.commit()?;
        Ok(())
    }

    pub fn list_invite_tokens(&self) -> Result<Vec<String>, DbError> {
        let read_txn = self.inner.begin_read()?;
        let table = read_txn.open_table(INVITE_TOKENS)?;
        let mut values = Vec::new();
        for entry in table.iter()? {
            let (_, v) = entry?;
            values.push(v.value().to_string());
        }
        Ok(values)
    }

    // --- Registration: AID Whitelist ---

    pub fn save_whitelist_entry(&self, aid: &str) -> Result<(), DbError> {
        let write_txn = self.inner.begin_write()?;
        {
            let mut table = write_txn.open_table(AID_WHITELIST)?;
            table.insert(aid, "1")?;
        }
        write_txn.commit()?;
        Ok(())
    }

    pub fn get_whitelist_entry(&self, aid: &str) -> Result<Option<String>, DbError> {
        let read_txn = self.inner.begin_read()?;
        let table = read_txn.open_table(AID_WHITELIST)?;
        Ok(table.get(aid)?.map(|v| v.value().to_string()))
    }

    pub fn delete_whitelist_entry(&self, aid: &str) -> Result<(), DbError> {
        let write_txn = self.inner.begin_write()?;
        {
            let mut table = write_txn.open_table(AID_WHITELIST)?;
            table.remove(aid)?;
        }
        write_txn.commit()?;
        Ok(())
    }

    pub fn list_whitelist_entries(&self) -> Result<Vec<String>, DbError> {
        let read_txn = self.inner.begin_read()?;
        let table = read_txn.open_table(AID_WHITELIST)?;
        let mut keys = Vec::new();
        for entry in table.iter()? {
            let (k, _) = entry?;
            keys.push(k.value().to_string());
        }
        Ok(keys)
    }
}
