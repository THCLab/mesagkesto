use std::collections::HashMap;

use keri::actor::prelude::SelfAddressingIdentifier;
use tokio::sync::{mpsc, oneshot};

pub enum ResponsesMessage {
    SaveMessage {
        digest: SelfAddressingIdentifier,
        message: String,
        // where to return result
        sender: oneshot::Sender<u32>,
    },
    GetByDigest {
        digest: SelfAddressingIdentifier,
        sender: oneshot::Sender<Option<String>>,
    },
}

pub struct ResponsesActor {
    // From where get messages
    receiver: mpsc::Receiver<ResponsesMessage>,
    responses: HashMap<SelfAddressingIdentifier, String>,
}

impl ResponsesActor {
    fn new(receiver: mpsc::Receiver<ResponsesMessage>) -> Self {
        ResponsesActor {
            receiver,
            responses: HashMap::new(),
        }
    }
    async fn handle_message(&mut self, msg: ResponsesMessage) {
        match msg {
            ResponsesMessage::SaveMessage {
                digest,
                message,
                sender,
            } => {
                self.responses.insert(digest, message);

                // The `let _ =` ignores any errors when sending.
                //
                // This can happen if the `select!` macro is used
                // to cancel waiting for the response.
                let _ = sender.send(1);
            }
            ResponsesMessage::GetByDigest { digest, sender } => {
                let res = self.responses.get(&digest).map(|d| d.to_owned());
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
    pub fn new() -> Self {
        let (sender, receiver) = mpsc::channel(8);
        let actor = ResponsesActor::new(receiver);
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

        // Ignore send errors. If this send fails, so does the
        // recv.await below. There's no reason to check for the
        // same failure twice.
        let _ = self.responder_sender.send(msg).await;
        recv.await.expect("Actor task has been killed")
    }

    pub async fn get_by_digest(&self, digest: SelfAddressingIdentifier) -> Option<String> {
        let (send, recv) = oneshot::channel();
        let msg = ResponsesMessage::GetByDigest {
            digest,
            sender: send,
        };

        // Ignore send errors. If this send fails, so does the
        // recv.await below. There's no reason to check for the
        // same failure twice.
        let _ = self.responder_sender.send(msg).await;
        recv.await.expect("Actor task has been killed")
    }
}

impl Default for ResponsesHandle {
    fn default() -> Self {
        Self::new()
    }
}
