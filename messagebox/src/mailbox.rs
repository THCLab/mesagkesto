use chrono::Utc;
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, info, warn};

use crate::db::Db;
use crate::MessageboxError;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, utoipa::ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum MailboxState {
    Provisioned,
    Active,
    Suspended,
    Deleted,
}

#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct MailboxMetadata {
    pub aid: String,
    pub state: MailboxState,
    pub created_at: String,
    pub updated_at: String,
}

pub enum MailboxMessage {
    Provision {
        aid: String,
        sender: oneshot::Sender<Result<MailboxMetadata, MessageboxError>>,
    },
    Activate {
        aid: String,
        sender: oneshot::Sender<Result<(), MessageboxError>>,
    },
    Get {
        aid: String,
        sender: oneshot::Sender<Option<MailboxMetadata>>,
    },
    Delete {
        aid: String,
        sender: oneshot::Sender<Result<(), MessageboxError>>,
    },
    Exists {
        aid: String,
        sender: oneshot::Sender<bool>,
    },
}

struct MailboxActor {
    receiver: mpsc::Receiver<MailboxMessage>,
    db: Db,
}

impl MailboxActor {
    fn new(receiver: mpsc::Receiver<MailboxMessage>, db: Db) -> Self {
        Self { receiver, db }
    }

    fn load_metadata(&self, aid: &str) -> Option<MailboxMetadata> {
        self.db
            .get_mailbox(aid)
            .ok()
            .flatten()
            .and_then(|json| serde_json::from_str(&json).ok())
    }

    fn save_metadata(&self, metadata: &MailboxMetadata) -> Result<(), MessageboxError> {
        let json = serde_json::to_string(metadata)
            .map_err(|e| MessageboxError::Unparsable(e.to_string()))?;
        self.db
            .save_mailbox(&metadata.aid, &json)
            .map_err(|e| MessageboxError::Unparsable(e.to_string()))
    }

    async fn handle_message(&mut self, msg: MailboxMessage) {
        match msg {
            MailboxMessage::Provision { aid, sender } => {
                debug!(aid = %aid, "Provisioning mailbox");
                let result = if self.load_metadata(&aid).is_some() {
                    warn!(aid = %aid, "Mailbox already exists, cannot provision");
                    Err(MessageboxError::AuthError(format!(
                        "Mailbox already exists for AID: {}",
                        aid
                    )))
                } else {
                    let now = Utc::now().to_rfc3339();
                    let metadata = MailboxMetadata {
                        aid: aid.clone(),
                        state: MailboxState::Provisioned,
                        created_at: now.clone(),
                        updated_at: now,
                    };
                    info!(aid = %aid, "Mailbox provisioned successfully");
                    self.save_metadata(&metadata).map(|_| metadata)
                };
                let _ = sender.send(result);
            }
            MailboxMessage::Activate { aid, sender } => {
                debug!(aid = %aid, "Activating mailbox");
                let result = match self.load_metadata(&aid) {
                    Some(mut meta) if meta.state == MailboxState::Provisioned => {
                        meta.state = MailboxState::Active;
                        meta.updated_at = Utc::now().to_rfc3339();
                        info!(aid = %aid, "Mailbox activated successfully");
                        self.save_metadata(&meta)
                    }
                    Some(meta) => {
                        debug!(aid = %aid, state = ?meta.state, "Mailbox already in active state");
                        Ok(()) // Already active or other state
                    }
                    None => {
                        warn!(aid = %aid, "Mailbox not found for activation");
                        Err(MessageboxError::AuthError("Mailbox not found".to_string()))
                    }
                };
                let _ = sender.send(result);
            }
            MailboxMessage::Get { aid, sender } => {
                debug!(aid = %aid, "Getting mailbox metadata");
                let meta = self.load_metadata(&aid);
                let _ = sender.send(meta);
            }
            MailboxMessage::Delete { aid, sender } => {
                debug!(aid = %aid, "Deleting mailbox");
                let result = match self.load_metadata(&aid) {
                    Some(mut meta) => {
                        meta.state = MailboxState::Deleted;
                        meta.updated_at = Utc::now().to_rfc3339();
                        info!(aid = %aid, "Mailbox marked as deleted");
                        self.save_metadata(&meta)
                    }
                    None => {
                        warn!(aid = %aid, "Mailbox not found for deletion");
                        Err(MessageboxError::AuthError("Mailbox not found".to_string()))
                    }
                };
                let _ = sender.send(result);
            }
            MailboxMessage::Exists { aid, sender } => {
                let exists = self
                    .load_metadata(&aid)
                    .map(|m| m.state != MailboxState::Deleted)
                    .unwrap_or(false);
                debug!(aid = %aid, exists = exists, "Checked mailbox existence");
                let _ = sender.send(exists);
            }
        }
    }
}

async fn run_mailbox_actor(mut actor: MailboxActor) {
    while let Some(msg) = actor.receiver.recv().await {
        actor.handle_message(msg).await;
    }
}

#[derive(Clone)]
pub struct MailboxHandle {
    sender: mpsc::Sender<MailboxMessage>,
}

impl MailboxHandle {
    pub fn new(db: Db) -> Self {
        let (sender, receiver) = mpsc::channel(8);
        let actor = MailboxActor::new(receiver, db);
        tokio::spawn(run_mailbox_actor(actor));
        Self { sender }
    }

    pub async fn provision(&self, aid: String) -> Result<MailboxMetadata, MessageboxError> {
        let (send, recv) = oneshot::channel();
        let msg = MailboxMessage::Provision { aid, sender: send };
        let _ = self.sender.send(msg).await;
        recv.await.map_err(|_| MessageboxError::KilledSender)?
    }

    pub async fn activate(&self, aid: String) -> Result<(), MessageboxError> {
        let (send, recv) = oneshot::channel();
        let msg = MailboxMessage::Activate { aid, sender: send };
        let _ = self.sender.send(msg).await;
        recv.await.map_err(|_| MessageboxError::KilledSender)?
    }

    pub async fn get(&self, aid: &str) -> Option<MailboxMetadata> {
        let (send, recv) = oneshot::channel();
        let msg = MailboxMessage::Get {
            aid: aid.to_string(),
            sender: send,
        };
        let _ = self.sender.send(msg).await;
        recv.await.ok()?
    }

    pub async fn delete(&self, aid: String) -> Result<(), MessageboxError> {
        let (send, recv) = oneshot::channel();
        let msg = MailboxMessage::Delete { aid, sender: send };
        let _ = self.sender.send(msg).await;
        recv.await.map_err(|_| MessageboxError::KilledSender)?
    }

    pub async fn exists(&self, aid: &str) -> bool {
        let (send, recv) = oneshot::channel();
        let msg = MailboxMessage::Exists {
            aid: aid.to_string(),
            sender: send,
        };
        let _ = self.sender.send(msg).await;
        recv.await.unwrap_or(false)
    }
}
