use std::collections::HashMap;

use serde_json::json;
use tokio::sync::{mpsc, oneshot};

use crate::notifier::NotifyHandle;

pub enum StorageMessage {
    SaveMessage {
        key: String,
        digest: String,
        message: String,
        // where to return result
        sender: oneshot::Sender<u32>,
    },
    GetBySn {
        key: String,
        index: usize,
        // where to return result
        sender: oneshot::Sender<Option<String>>,
    },
    GetByDigest {
        key: String,
        digests: Vec<String>,
        sender: oneshot::Sender<Option<String>>,
    },
}

pub struct StorageActor {
    // From where get messages
    receiver: mpsc::Receiver<StorageMessage>,
    messages: HashMap<String, Vec<(String, String)>>,
    notify_handle: NotifyHandle,
}

impl StorageActor {
    fn new(receiver: mpsc::Receiver<StorageMessage>, notify_handle: NotifyHandle) -> Self {
        StorageActor {
            receiver,
            messages: HashMap::new(),
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
                let block_for_issuer = self.messages.get_mut(&key);
                match block_for_issuer {
                    Some(issuance_list) => issuance_list.push((digest.clone(), message)),
                    None => {
                        self.messages
                            .insert(key.clone(), vec![(digest.clone(), message)]);
                    }
                };
                self.notify_handle.notify(key, digest).await;

                // The `let _ =` ignores any errors when sending.
                //
                // This can happen if the `select!` macro is used
                // to cancel waiting for the response.
                let _ = sender.send(1);
            }
            StorageMessage::GetBySn { key, sender, index } => {
                match self.messages.get(&key).map(|r| r.to_owned()) {
                    Some(crud) => {
                        let last_id = crud.len() - 1;
                        let out = crud.get(index..).map(|el| {
                            let messages = el
                                .iter()
                                .map(|(_digest, msg)| msg)
                                .fold(String::new(), |a, b| a + b);
                            json!({"last_sn":last_id,"messages":messages}).to_string()
                        });
                        let _ = sender.send(out);
                    }
                    None => {
                        let _ = sender.send(None);
                    }
                }
            }
            StorageMessage::GetByDigest {
                key,
                digests: digest,
                sender,
            } => match self.messages.get(&key).map(|r| r.to_owned()) {
                Some(crud) => {
                    let out = crud
                        .into_iter()
                        .filter_map(|(dig, value)| {
                            if digest.contains(&dig) {
                                Some(value)
                            } else {
                                None
                            }
                        })
                        .fold(String::new(), |a, b| a + &b);

                    let _ = sender.send(Some(out));
                }
                None => {
                    let _ = sender.send(None);
                }
            },
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
    pub fn new(notify_handle: NotifyHandle) -> Self {
        let (sender, receiver) = mpsc::channel(8);
        let actor = StorageActor::new(receiver, notify_handle);
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
            message: value,
            sender: send,
        };

        // Ignore send errors. If this send fails, so does the
        // recv.await below. There's no reason to check for the
        // same failure twice.
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

        // Ignore send errors. If this send fails, so does the
        // recv.await below. There's no reason to check for the
        // same failure twice.
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

        // Ignore send errors. If this send fails, so does the
        // recv.await below. There's no reason to check for the
        // same failure twice.
        let _ = self.database_sender.send(msg).await;
        recv.await.expect("Actor task has been killed")
    }
}
