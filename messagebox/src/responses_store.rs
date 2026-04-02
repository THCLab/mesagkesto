use keri_core::actor::prelude::SelfAddressingIdentifier;
use tokio::sync::{mpsc, oneshot};

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
                match self.db.save_response(&digest_str, &message) {
                    Ok(()) => {
                        let _ = sender.send(1);
                    }
                    Err(e) => {
                        eprintln!("Failed to save response: {}", e);
                        let _ = sender.send(0);
                    }
                }
            }
            ResponsesMessage::GetByDigest { digest, sender } => {
                let digest_str = digest.to_string();
                let res = match self.db.get_response(&digest_str) {
                    Ok(val) => val,
                    Err(e) => {
                        eprintln!("Failed to get response: {}", e);
                        None
                    }
                };
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
