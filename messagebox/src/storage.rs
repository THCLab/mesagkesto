use serde_json::json;
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, info, warn};

use crate::db::Db;
use crate::notifier::NotifyHandle;

pub type Message = serde_json::Value;

pub enum StorageMessage {
    SaveMessage {
        key: String,
        digest: String,
        message: Message,
        sender: oneshot::Sender<u32>,
    },
    GetBySn {
        key: String,
        index: usize,
        sender: oneshot::Sender<Option<String>>,
    },
    GetByDigest {
        key: String,
        digests: Vec<String>,
        sender: oneshot::Sender<Option<String>>,
    },
}

pub struct StorageActor {
    receiver: mpsc::Receiver<StorageMessage>,
    db: Db,
    notify_handle: NotifyHandle,
}

impl StorageActor {
    fn new(receiver: mpsc::Receiver<StorageMessage>, db: Db, notify_handle: NotifyHandle) -> Self {
        StorageActor {
            receiver,
            db,
            notify_handle,
        }
    }

    async fn handle_message(&mut self, msg: StorageMessage) {
        match msg {
            StorageMessage::SaveMessage {
                key,
                digest,
                message,
                sender,
            } => {
                let msg_str = message.to_string();
                debug!(key = %key, digest = %digest, msg_len = msg_str.len(), "Saving message");
                match self.db.save_message(&key, &digest, &msg_str) {
                    Ok(seq) => {
                        info!(key = %key, digest = %digest, seq = seq, "Message saved successfully, notifying");
                        debug!(key = %key, digest = %digest, "Sending notification");
                        self.notify_handle.notify(key, digest).await;
                        let _ = sender.send(1);
                    }
                    Err(e) => {
                        warn!(key = %key, digest = %digest, error = %e, "Failed to save message");
                        let _ = sender.send(0);
                    }
                }
            }
            StorageMessage::GetBySn { key, sender, index } => {
                debug!(key = %key, index = index, "Getting messages by sequence number");
                let result = match self.db.get_messages_by_sn(&key, index) {
                    Ok(Some((last_sn, messages))) => {
                        debug!(key = %key, last_sn = last_sn, count = messages.len(), "Got messages by sn");
                        info!(key = %key, last_sn = last_sn, message_count = messages.len(), "Messages retrieved by sn");
                        let parsed: Vec<serde_json::Value> = messages
                            .iter()
                            .filter_map(|m| serde_json::from_str(m).ok())
                            .collect();
                        Some(json!({"last_sn": last_sn, "messages": parsed}).to_string())
                    }
                    Ok(None) => {
                        debug!(key = %key, index = index, "No messages found for sequence number");
                        None
                    }
                    Err(e) => {
                        warn!(key = %key, index = index, error = %e, "Failed to get messages by sn");
                        None
                    }
                };
                let _ = sender.send(result);
            }
            StorageMessage::GetByDigest {
                key,
                digests,
                sender,
            } => {
                debug!(key = %key, digest_count = digests.len(), "Getting messages by digest");
                let result = match self.db.get_messages_by_digest(&key, &digests) {
                    Ok(Some(messages)) => {
                        debug!(key = %key, count = messages.len(), "Got messages by digest");
                        info!(key = %key, message_count = messages.len(), "Messages retrieved by digest");
                        let parsed: Vec<serde_json::Value> = messages
                            .iter()
                            .filter_map(|m| serde_json::from_str(m).ok())
                            .collect();
                        serde_json::to_string(&parsed).ok()
                    }
                    Ok(None) => {
                        debug!(key = %key, "No messages found for digests");
                        None
                    }
                    Err(e) => {
                        warn!(key = %key, error = %e, "Failed to get messages by digest");
                        None
                    }
                };
                let _ = sender.send(result);
            }
        }
    }
}

async fn run_my_actor(mut actor: StorageActor) {
    while let Some(msg) = actor.receiver.recv().await {
        actor.handle_message(msg).await;
    }
}

#[derive(Clone)]
pub struct StorageHandle {
    database_sender: mpsc::Sender<StorageMessage>,
}

impl StorageHandle {
    pub fn new(db: Db, notify_handle: NotifyHandle) -> Self {
        let (sender, receiver) = mpsc::channel(8);
        let actor = StorageActor::new(receiver, db.clone(), notify_handle);
        tokio::spawn(run_my_actor(actor));
        debug!("Storage actor initialized");

        Self {
            database_sender: sender,
        }
    }

    pub async fn save(&self, key: String, value: String, digest: String) -> u32 {
        let (send, recv) = oneshot::channel();
        let msg = StorageMessage::SaveMessage {
            key,
            digest,
            message: json!(value),
            sender: send,
        };

        let _ = self.database_sender.send(msg).await;
        recv.await.expect("Actor task has been killed")
    }

    pub async fn get_by_index(&self, id: &str, index: usize) -> Option<String> {
        let (send, recv) = oneshot::channel();
        let msg = StorageMessage::GetBySn {
            key: id.to_string(),
            index,
            sender: send,
        };

        let _ = self.database_sender.send(msg).await;
        recv.await.expect("Actor task has been killed")
    }

    pub async fn get_by_digest(&self, id: &str, digests: Vec<String>) -> Option<String> {
        let (send, recv) = oneshot::channel();
        let msg = StorageMessage::GetByDigest {
            key: id.to_string(),
            digests,
            sender: send,
        };

        let _ = self.database_sender.send(msg).await;
        recv.await.expect("Actor task has been killed")
    }
}
