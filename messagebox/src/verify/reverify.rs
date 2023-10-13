use std::collections::HashMap;

use keri::actor::prelude::SelfAddressingIdentifier;
use tokio::sync::{mpsc, oneshot};

use crate::MessageboxError;

use super::signer::SignerHandle;

#[derive(Debug)]
pub enum ReverifyMessage {
    Save {
		digest: SelfAddressingIdentifier,
        message: String,
    },
}


pub struct ReverifyActor {
    signer: SignerHandle,
    reverify_dict: HashMap<SelfAddressingIdentifier, String>,
    // From where get messages
    receiver: mpsc::Receiver<ReverifyMessage>,
}

impl ReverifyActor {
    fn new(
        signer: SignerHandle,
        receiver: mpsc::Receiver<ReverifyMessage>,
    ) -> Self {
        ReverifyActor {
            signer,
            reverify_dict: HashMap::new(),
            receiver,
        }
    }
    async fn handle_message(&mut self, msg: ReverifyMessage) {
        match msg {
            ReverifyMessage::Save { digest, message } => {
                println!("Saving to verify later: {}", &message);
                self.reverify_dict.insert(digest, message);
            },
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
    pub fn new(signer: SignerHandle) -> Self {
        let (sender, receiver) = mpsc::channel(8);
        let actor = ReverifyActor::new(signer, receiver);
        tokio::spawn(run_my_actor(actor));

        Self {
            validate_sender: sender,
        }
    }

    pub async fn save(&self, key: SelfAddressingIdentifier, message: String) -> Result<(), MessageboxError> {
        let msg = ReverifyMessage::Save { digest: key, message };

        // Ignore send errors. If this send fails, so does the
        // recv.await below. There's no reason to check for the
        // same failure twice.
        let _ = self.validate_sender.send(msg).await;
        Ok(())
    }
}
