use chrono::Utc;
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, info, warn};
use uuid::Uuid;

use crate::db::Db;
use crate::MessageboxError;

/// Server registration policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegistrationMode {
    /// Anyone with a KERI AID can register.
    Public,
    /// Registration requires a valid invite token or AID whitelist entry.
    InviteOnly,
}

impl RegistrationMode {
    pub fn from_str_config(s: Option<&str>) -> Self {
        match s {
            Some("invite_only") => Self::InviteOnly,
            _ => Self::Public,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct InviteToken {
    pub token: String,
    pub created_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

pub enum RegistrationMessage {
    /// Validate that an AID (+ optional invite token) may register.
    /// Does NOT consume the invite token.
    CheckAccess {
        aid: String,
        invite_token: Option<String>,
        sender: oneshot::Sender<Result<(), MessageboxError>>,
    },
    /// Consume (delete) an invite token after successful registration.
    ConsumeInvite {
        token: String,
        sender: oneshot::Sender<Result<(), MessageboxError>>,
    },
    /// Generate a new invite token.
    CreateInvite {
        label: Option<String>,
        sender: oneshot::Sender<Result<InviteToken, MessageboxError>>,
    },
    /// List all active invite tokens.
    ListInvites {
        sender: oneshot::Sender<Vec<InviteToken>>,
    },
    /// Revoke (delete) an invite token.
    RevokeInvite {
        token: String,
        sender: oneshot::Sender<bool>,
    },
    /// Add an AID to the registration whitelist.
    AddWhitelist {
        aid: String,
        sender: oneshot::Sender<Result<(), MessageboxError>>,
    },
    /// Remove an AID from the registration whitelist.
    RemoveWhitelist {
        aid: String,
        sender: oneshot::Sender<bool>,
    },
    /// List all whitelisted AIDs.
    ListWhitelist {
        sender: oneshot::Sender<Vec<String>>,
    },
}

struct RegistrationActor {
    receiver: mpsc::Receiver<RegistrationMessage>,
    db: Db,
    mode: RegistrationMode,
}

impl RegistrationActor {
    fn new(receiver: mpsc::Receiver<RegistrationMessage>, db: Db, mode: RegistrationMode) -> Self {
        Self {
            receiver,
            db,
            mode,
        }
    }

    async fn handle_message(&mut self, msg: RegistrationMessage) {
        match msg {
            RegistrationMessage::CheckAccess {
                aid,
                invite_token,
                sender,
            } => {
                let result = self.check_access(&aid, invite_token.as_deref());
                let _ = sender.send(result);
            }
            RegistrationMessage::ConsumeInvite { token, sender } => {
                let result = self.consume_invite(&token);
                let _ = sender.send(result);
            }
            RegistrationMessage::CreateInvite { label, sender } => {
                let result = self.create_invite(label);
                let _ = sender.send(result);
            }
            RegistrationMessage::ListInvites { sender } => {
                let tokens = self.list_invites();
                let _ = sender.send(tokens);
            }
            RegistrationMessage::RevokeInvite { token, sender } => {
                let revoked = self.revoke_invite(&token);
                let _ = sender.send(revoked);
            }
            RegistrationMessage::AddWhitelist { aid, sender } => {
                let result = self.add_whitelist(&aid);
                let _ = sender.send(result);
            }
            RegistrationMessage::RemoveWhitelist { aid, sender } => {
                let removed = self.remove_whitelist(&aid);
                let _ = sender.send(removed);
            }
            RegistrationMessage::ListWhitelist { sender } => {
                let aids = self.list_whitelist();
                let _ = sender.send(aids);
            }
        }
    }

    fn check_access(&self, aid: &str, invite_token: Option<&str>) -> Result<(), MessageboxError> {
        if self.mode == RegistrationMode::Public {
            return Ok(());
        }

        // Check AID whitelist
        if let Ok(Some(_)) = self.db.get_whitelist_entry(aid) {
            debug!(aid = %aid, "Registration allowed: AID is whitelisted");
            return Ok(());
        }

        // Check invite token
        if let Some(token) = invite_token {
            if let Ok(Some(_)) = self.db.get_invite_token(token) {
                debug!(aid = %aid, "Registration allowed: valid invite token provided");
                return Ok(());
            }
        }

        warn!(aid = %aid, "Registration denied: invite-only mode, no valid invite or whitelist entry");
        Err(MessageboxError::RegistrationDenied(
            "invite-only mode: provide a valid invite token or contact the server administrator"
                .to_string(),
        ))
    }

    fn consume_invite(&self, token: &str) -> Result<(), MessageboxError> {
        self.db
            .delete_invite_token(token)
            .map_err(|e| MessageboxError::DbError(e.to_string()))?;
        info!(token = %token, "Invite token consumed");
        Ok(())
    }

    fn create_invite(&self, label: Option<String>) -> Result<InviteToken, MessageboxError> {
        let token_hex = Uuid::new_v4().to_string();
        let created_at = Utc::now().to_rfc3339();

        let invite = InviteToken {
            token: token_hex.clone(),
            created_at,
            label,
        };
        let json = serde_json::to_string(&invite)
            .map_err(|e| MessageboxError::Unparsable(e.to_string()))?;

        self.db
            .save_invite_token(&token_hex, &json)
            .map_err(|e| MessageboxError::DbError(e.to_string()))?;

        info!(token = %token_hex, "Invite token created");
        Ok(invite)
    }

    fn list_invites(&self) -> Vec<InviteToken> {
        self.db
            .list_invite_tokens()
            .unwrap_or_default()
            .into_iter()
            .filter_map(|json| serde_json::from_str::<InviteToken>(&json).ok())
            .collect()
    }

    fn revoke_invite(&self, token: &str) -> bool {
        match self.db.delete_invite_token(token) {
            Ok(()) => {
                info!(token = %token, "Invite token revoked");
                true
            }
            Err(e) => {
                warn!(token = %token, error = %e, "Failed to revoke invite token");
                false
            }
        }
    }

    fn add_whitelist(&self, aid: &str) -> Result<(), MessageboxError> {
        self.db
            .save_whitelist_entry(aid)
            .map_err(|e| MessageboxError::DbError(e.to_string()))?;
        info!(aid = %aid, "AID added to registration whitelist");
        Ok(())
    }

    fn remove_whitelist(&self, aid: &str) -> bool {
        match self.db.delete_whitelist_entry(aid) {
            Ok(()) => {
                info!(aid = %aid, "AID removed from registration whitelist");
                true
            }
            Err(e) => {
                warn!(aid = %aid, error = %e, "Failed to remove AID from whitelist");
                false
            }
        }
    }

    fn list_whitelist(&self) -> Vec<String> {
        self.db.list_whitelist_entries().unwrap_or_default()
    }
}

async fn run_registration_actor(mut actor: RegistrationActor) {
    while let Some(msg) = actor.receiver.recv().await {
        actor.handle_message(msg).await;
    }
}

#[derive(Clone)]
pub struct RegistrationHandle {
    sender: mpsc::Sender<RegistrationMessage>,
}

impl RegistrationHandle {
    pub fn new(db: Db, mode: RegistrationMode) -> Self {
        let (sender, receiver) = mpsc::channel(8);
        let actor = RegistrationActor::new(receiver, db, mode.clone());
        tokio::spawn(run_registration_actor(actor));
        info!(mode = ?mode, "Registration actor initialized");
        Self { sender }
    }

    pub async fn check_access(
        &self,
        aid: String,
        invite_token: Option<String>,
    ) -> Result<(), MessageboxError> {
        let (send, recv) = oneshot::channel();
        let msg = RegistrationMessage::CheckAccess {
            aid,
            invite_token,
            sender: send,
        };
        let _ = self.sender.send(msg).await;
        recv.await.map_err(|_| MessageboxError::KilledSender)?
    }

    pub async fn consume_invite(&self, token: String) -> Result<(), MessageboxError> {
        let (send, recv) = oneshot::channel();
        let msg = RegistrationMessage::ConsumeInvite {
            token,
            sender: send,
        };
        let _ = self.sender.send(msg).await;
        recv.await.map_err(|_| MessageboxError::KilledSender)?
    }

    pub async fn create_invite(
        &self,
        label: Option<String>,
    ) -> Result<InviteToken, MessageboxError> {
        let (send, recv) = oneshot::channel();
        let msg = RegistrationMessage::CreateInvite {
            label,
            sender: send,
        };
        let _ = self.sender.send(msg).await;
        recv.await.map_err(|_| MessageboxError::KilledSender)?
    }

    pub async fn list_invites(&self) -> Vec<InviteToken> {
        let (send, recv) = oneshot::channel();
        let msg = RegistrationMessage::ListInvites { sender: send };
        let _ = self.sender.send(msg).await;
        recv.await.unwrap_or_default()
    }

    pub async fn revoke_invite(&self, token: String) -> bool {
        let (send, recv) = oneshot::channel();
        let msg = RegistrationMessage::RevokeInvite {
            token,
            sender: send,
        };
        let _ = self.sender.send(msg).await;
        recv.await.unwrap_or(false)
    }

    pub async fn add_whitelist(&self, aid: String) -> Result<(), MessageboxError> {
        let (send, recv) = oneshot::channel();
        let msg = RegistrationMessage::AddWhitelist {
            aid,
            sender: send,
        };
        let _ = self.sender.send(msg).await;
        recv.await.map_err(|_| MessageboxError::KilledSender)?
    }

    pub async fn remove_whitelist(&self, aid: String) -> bool {
        let (send, recv) = oneshot::channel();
        let msg = RegistrationMessage::RemoveWhitelist {
            aid,
            sender: send,
        };
        let _ = self.sender.send(msg).await;
        recv.await.unwrap_or(false)
    }

    pub async fn list_whitelist(&self) -> Vec<String> {
        let (send, recv) = oneshot::channel();
        let msg = RegistrationMessage::ListWhitelist { sender: send };
        let _ = self.sender.send(msg).await;
        recv.await.unwrap_or_default()
    }
}
