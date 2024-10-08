use std::collections::HashMap;

use keri_controller::IdentifierPrefix;
use keri_core::event_message::signature::Signature;
use tokio::sync::{mpsc, oneshot};

use crate::MessageboxError;

#[derive(Debug)]
pub enum ReverifyMessage {
    Save {
        id: IdentifierPrefix,
        // digest: SelfAddressingIdentifier,
        message: String,
        signatures: Vec<Signature>,
    },
    Get {
        id: IdentifierPrefix,
        sender: oneshot::Sender<(Vec<u8>, Vec<Signature>)>,
    },
}

pub struct ReverifyActor {
    reverify_dict: HashMap<IdentifierPrefix, (Vec<u8>, Vec<Signature>)>,
    // From where get messages
    receiver: mpsc::Receiver<ReverifyMessage>,
}

impl ReverifyActor {
    fn new(receiver: mpsc::Receiver<ReverifyMessage>) -> Self {
        ReverifyActor {
            reverify_dict: HashMap::new(),
            receiver,
        }
    }
    async fn handle_message(&mut self, msg: ReverifyMessage) {
        match msg {
            // ReverifyMessage::Save { digest, message } => {
            ReverifyMessage::Save {
                id,
                message,
                signatures,
            } => {
                println!("\nSaving to verify later: {}", &message);
                self.reverify_dict
                    .insert(id, (message.as_bytes().to_vec(), signatures));
            }
            ReverifyMessage::Get { id, sender } => {
                let message = self.reverify_dict.get(&id);
                sender.send(message.unwrap().clone()).unwrap();
            }
        }
    }
}

async fn run_my_actor(mut actor: ReverifyActor) {
    while let Some(msg) = actor.receiver.recv().await {
        actor.handle_message(msg).await
    }
}

#[derive(Clone)]
pub struct ReverifyHandle {
    validate_sender: mpsc::Sender<ReverifyMessage>,
}

impl ReverifyHandle {
    pub fn new() -> Self {
        let (sender, receiver) = mpsc::channel(8);
        let actor = ReverifyActor::new(receiver);
        tokio::spawn(run_my_actor(actor));

        Self {
            validate_sender: sender,
        }
    }

    pub async fn save(
        &self,
        id: IdentifierPrefix,
        message: String,
        signatures: Vec<Signature>,
    ) -> Result<(), MessageboxError> {
        let msg = ReverifyMessage::Save {
            id,
            message,
            signatures,
        };

        // Ignore send errors. If this send fails, so does the
        // recv.await below. There's no reason to check for the
        // same failure twice.
        let _ = self.validate_sender.send(msg).await;
        Ok(())
    }

    pub async fn get(
        &self,
        identifier: IdentifierPrefix,
    ) -> Result<(Vec<u8>, Vec<Signature>), MessageboxError> {
        let (send, recv) = oneshot::channel();
        let msg = ReverifyMessage::Get {
            id: identifier,
            sender: send,
        };

        // Ignore send errors. If this send fails, so does the
        // recv.await below. There's no reason to check for the
        // same failure twice.
        let _ = self.validate_sender.send(msg).await;
        Ok(recv.await.expect("Err"))
    }
}
