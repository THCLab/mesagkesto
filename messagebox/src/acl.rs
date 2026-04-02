use std::collections::HashSet;

use tokio::sync::{mpsc, oneshot};

use crate::db::Db;
use crate::MessageboxError;

pub enum AclMessage {
    /// Replace the full ACL token set for a mailbox
    SetTokens {
        aid: String,
        tokens: Vec<String>,
        sender: oneshot::Sender<Result<(), MessageboxError>>,
    },
    /// Check if a given auth token is in the mailbox's ACL
    CheckToken {
        aid: String,
        token: String,
        sender: oneshot::Sender<bool>,
    },
    /// Get all tokens for an AID
    GetTokens {
        aid: String,
        sender: oneshot::Sender<Vec<String>>,
    },
}

struct AclActor {
    receiver: mpsc::Receiver<AclMessage>,
    db: Db,
    /// In-memory cache: aid -> set of hex-encoded tokens
    cache: std::collections::HashMap<String, HashSet<String>>,
}

impl AclActor {
    fn new(receiver: mpsc::Receiver<AclMessage>, db: Db) -> Self {
        Self {
            receiver,
            db,
            cache: std::collections::HashMap::new(),
        }
    }

    fn load_tokens(&mut self, aid: &str) -> &HashSet<String> {
        if !self.cache.contains_key(aid) {
            let tokens = self
                .db
                .get_acl_tokens(aid)
                .ok()
                .flatten()
                .and_then(|json| serde_json::from_str::<Vec<String>>(&json).ok())
                .unwrap_or_default();
            self.cache
                .insert(aid.to_string(), tokens.into_iter().collect());
        }
        self.cache.get(aid).unwrap()
    }

    async fn handle_message(&mut self, msg: AclMessage) {
        match msg {
            AclMessage::SetTokens {
                aid,
                tokens,
                sender,
            } => {
                let result = match serde_json::to_string(&tokens) {
                    Ok(json) => self
                        .db
                        .save_acl_tokens(&aid, &json)
                        .map_err(|e| MessageboxError::Unparsable(e.to_string())),
                    Err(e) => Err(MessageboxError::Unparsable(e.to_string())),
                };
                if result.is_ok() {
                    self.cache
                        .insert(aid, tokens.into_iter().collect());
                }
                let _ = sender.send(result);
            }
            AclMessage::CheckToken { aid, token, sender } => {
                let tokens = self.load_tokens(&aid);
                let _ = sender.send(tokens.contains(&token));
            }
            AclMessage::GetTokens { aid, sender } => {
                let tokens = self.load_tokens(&aid);
                let _ = sender.send(tokens.iter().cloned().collect());
            }
        }
    }
}

async fn run_acl_actor(mut actor: AclActor) {
    while let Some(msg) = actor.receiver.recv().await {
        actor.handle_message(msg).await;
    }
}

#[derive(Clone)]
pub struct AclHandle {
    sender: mpsc::Sender<AclMessage>,
}

impl AclHandle {
    pub fn new(db: Db) -> Self {
        let (sender, receiver) = mpsc::channel(8);
        let actor = AclActor::new(receiver, db);
        tokio::spawn(run_acl_actor(actor));
        Self { sender }
    }

    /// Replace the entire ACL token set for a mailbox
    pub async fn set_tokens(
        &self,
        aid: String,
        tokens: Vec<String>,
    ) -> Result<(), MessageboxError> {
        let (send, recv) = oneshot::channel();
        let msg = AclMessage::SetTokens {
            aid,
            tokens,
            sender: send,
        };
        let _ = self.sender.send(msg).await;
        recv.await.map_err(|_| MessageboxError::KilledSender)?
    }

    /// Check if a given auth_token is allowed to write to the given AID's mailbox
    pub async fn check_token(&self, aid: &str, token: &str) -> bool {
        let (send, recv) = oneshot::channel();
        let msg = AclMessage::CheckToken {
            aid: aid.to_string(),
            token: token.to_string(),
            sender: send,
        };
        let _ = self.sender.send(msg).await;
        recv.await.unwrap_or(false)
    }

    /// Get all tokens for an AID
    pub async fn get_tokens(&self, aid: &str) -> Vec<String> {
        let (send, recv) = oneshot::channel();
        let msg = AclMessage::GetTokens {
            aid: aid.to_string(),
            sender: send,
        };
        let _ = self.sender.send(msg).await;
        recv.await.unwrap_or_default()
    }
}
