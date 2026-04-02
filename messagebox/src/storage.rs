use serde_json::json;
use tokio::sync::{mpsc, oneshot};

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
                match self.db.save_message(&key, &digest, &msg_str) {
                    Ok(_seq) => {
                        self.notify_handle.notify(key, digest).await;
                        let _ = sender.send(1);
                    }
                    Err(e) => {
                        eprintln!("Failed to save message: {}", e);
                        let _ = sender.send(0);
                    }
                }
            }
            StorageMessage::GetBySn { key, sender, index } => {
                let result = match self.db.get_messages_by_sn(&key, index) {
                    Ok(Some((last_sn, messages))) => {
                        let parsed: Vec<serde_json::Value> = messages
                            .iter()
                            .filter_map(|m| serde_json::from_str(m).ok())
                            .collect();
                        Some(json!({"last_sn": last_sn, "messages": parsed}).to_string())
                    }
                    Ok(None) => None,
                    Err(e) => {
                        eprintln!("Failed to get messages by sn: {}", e);
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
                let result = match self.db.get_messages_by_digest(&key, &digests) {
                    Ok(Some(messages)) => {
                        let parsed: Vec<serde_json::Value> = messages
                            .iter()
                            .filter_map(|m| serde_json::from_str(m).ok())
                            .collect();
                        serde_json::to_string(&parsed).ok()
                    }
                    Ok(None) => None,
                    Err(e) => {
                        eprintln!("Failed to get messages by digest: {}", e);
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
