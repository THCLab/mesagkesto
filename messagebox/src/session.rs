use redb::TableDefinition;
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

use crate::db::Db;

const SESSIONS: TableDefinition<&str, &str> = TableDefinition::new("sessions");

#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
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
        } else {
            debug!("Sessions table initialized");
        }
        Self { db }
    }

    pub fn save(&self, session: &Session) {
        debug!(aid = %session.aid, token = %session.token, expires_at = %session.expires_at, "Saving session");
        let json = match serde_json::to_string(session) {
            Ok(j) => j,
            Err(e) => {
                warn!(error = %e, "Failed to serialize session");
                return;
            }
        };
        if let Err(e) = self.db.put(SESSIONS, &session.token, &json) {
            warn!(error = %e, "Failed to save session to database");
        } else {
            info!(aid = %session.aid, "Session saved successfully");
        }
    }

    pub fn validate(&self, token: &str) -> Option<Session> {
        debug!(token = %token, "Validating session");
        match self.db.get(SESSIONS, token) {
            Ok(Some(json)) => {
                let session: Session = serde_json::from_str(&json).ok()?;
                if session.is_valid() {
                    info!(aid = %session.aid, "Session validated successfully");
                    Some(session)
                } else {
                    debug!(aid = %session.aid, "Session expired, removing");
                    // Expired — clean up
                    let _ = self.db.delete(SESSIONS, token);
                    None
                }
            }
            _ => {
                debug!(token = %token, "Session not found");
                None
            }
        }
    }

    pub fn revoke(&self, token: &str) -> bool {
        debug!(token = %token, "Revoking session");
        let result = self.db.delete(SESSIONS, token).is_ok();
        if result {
            info!("Session revoked successfully");
        } else {
            warn!("Failed to revoke session");
        }
        result
    }
}
