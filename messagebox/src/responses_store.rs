use keri_sdk::SelfAddressingIdentifier;
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, info, warn};

use crate::db::Db;

pub enum ResponsesMessage {
    SaveMessage {
        digest: SelfAddressingIdentifier,
        message: String,
        sender: oneshot::Sender<u32>,
    },
    GetByDigest {
        digest: SelfAddressingIdentifier,
        sender: oneshot::Sender<Option<String>>,
    },
}

pub struct ResponsesActor {
    receiver: mpsc::Receiver<ResponsesMessage>,
    db: Db,
}

impl ResponsesActor {
    fn new(receiver: mpsc::Receiver<ResponsesMessage>, db: Db) -> Self {
        ResponsesActor { receiver, db }
    }

    async fn handle_message(&mut self, msg: ResponsesMessage) {
        match msg {
            ResponsesMessage::SaveMessage {
                digest,
                message,
                sender,
            } => {
                let digest_str = digest.to_string();
                debug!(digest = %digest_str, msg_len = message.len(), "Saving response");
                match self.db.save_response(&digest_str, &message) {
                    Ok(()) => {
                        info!(digest = %digest_str, "Response saved successfully");
                        let _ = sender.send(1);
                    }
                    Err(e) => {
                        warn!(digest = %digest_str, error = %e, "Failed to save response");
                        let _ = sender.send(0);
                    }
                }
            }
            ResponsesMessage::GetByDigest { digest, sender } => {
                let digest_str = digest.to_string();
                debug!(digest = %digest_str, "Getting response");
                let res = match self.db.get_response(&digest_str) {
                    Ok(val) => val,
                    Err(e) => {
                        warn!(digest = %digest_str, error = %e, "Failed to get response");
                        None
                    }
                };
                match &res {
                    Some(_) => debug!(digest = %digest_str, "Response found"),
                    None => debug!(digest = %digest_str, "Response not found"),
                }
                let _ = sender.send(res);
            }
        }
    }
}

async fn run_my_actor(mut actor: ResponsesActor) {
    while let Some(msg) = actor.receiver.recv().await {
        actor.handle_message(msg).await;
    }
}

#[derive(Clone)]
pub struct ResponsesHandle {
    responder_sender: mpsc::Sender<ResponsesMessage>,
}

impl ResponsesHandle {
    pub fn new(db: Db) -> Self {
        let (sender, receiver) = mpsc::channel(8);
        let actor = ResponsesActor::new(receiver, db);
        tokio::spawn(run_my_actor(actor));
        debug!("Responses actor initialized");

        Self {
            responder_sender: sender,
        }
    }

    pub async fn save(&self, value: String, digest: SelfAddressingIdentifier) -> u32 {
        let (send, recv) = oneshot::channel();
        let msg = ResponsesMessage::SaveMessage {
            digest,
            message: value,
            sender: send,
        };

        let _ = self.responder_sender.send(msg).await;
        recv.await.expect("Actor task has been killed")
    }

    pub async fn get_by_digest(&self, digest: SelfAddressingIdentifier) -> Option<String> {
        let (send, recv) = oneshot::channel();
        let msg = ResponsesMessage::GetByDigest {
            digest,
            sender: send,
        };

        let _ = self.responder_sender.send(msg).await;
        recv.await.expect("Actor task has been killed")
    }
}
