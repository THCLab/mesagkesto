use redb::TableDefinition;
use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

use crate::db::Db;

const SESSIONS: TableDefinition<&str, &str> = TableDefinition::new("sessions");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub token: String,
    pub account_id: String,
    pub aid: String,
    pub expires_at: String,
}

impl Session {
    pub fn is_valid(&self) -> bool {
        use chrono::Utc;
        match self.expires_at.parse::<chrono::DateTime<chrono::Utc>>() {
            Ok(exp) => Utc::now() < exp,
            Err(_) => false,
        }
    }
}

pub struct SessionStore {
    db: Db,
}

impl SessionStore {
    pub fn new(db: Db) -> Self {
        // Ensure table exists
        if let Err(e) = db.ensure_table(SESSIONS) {
            warn!(error = %e, "Failed to create sessions table");
        }
        Self { db }
    }

    pub fn save(&self, session: &Session) {
        debug!(aid = %session.aid, token = %session.token, "Saving session");
        let json = match serde_json::to_string(session) {
            Ok(j) => j,
            Err(e) => {
                warn!(error = %e, "Failed to serialize session");
                return;
            }
        };
        if let Err(e) = self.db.put(SESSIONS, &session.token, &json) {
            warn!(error = %e, "Failed to save session");
        }
    }

    pub fn validate(&self, token: &str) -> Option<Session> {
        match self.db.get(SESSIONS, token) {
            Ok(Some(json)) => {
                let session: Session = serde_json::from_str(&json).ok()?;
                if session.is_valid() {
                    Some(session)
                } else {
                    // Expired — clean up
                    let _ = self.db.delete(SESSIONS, token);
                    None
                }
            }
            _ => None,
        }
    }

    pub fn revoke(&self, token: &str) -> bool {
        self.db.delete(SESSIONS, token).is_ok()
    }
}
