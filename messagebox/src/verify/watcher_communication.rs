use controller::IdentifierPrefix;
use keri::actor::prelude::SelfAddressingIdentifier;
use tokio::sync::{mpsc, oneshot};

use crate::MessageboxError;

#[derive(Debug)]
pub enum WatcherMessage {
    Find {
		identifier: IdentifierPrefix,
		digest: SelfAddressingIdentifier,
    },
}

pub struct WatcherCommunicationActor {
    // From where get messages
    receiver: mpsc::Receiver<WatcherMessage>,
}

impl WatcherCommunicationActor {
    fn new(
        receiver: mpsc::Receiver<WatcherMessage>,
    ) -> Self {
        WatcherCommunicationActor {
            receiver,
        }
    }
    async fn handle_message(&mut self, msg: WatcherMessage) {
        match msg {
            WatcherMessage::Find { identifier, digest } => todo!(),
        }
    }
}

async fn run_my_actor(mut actor: WatcherCommunicationActor) {
    while let Some(msg) = actor.receiver.recv().await {
        actor.handle_message(msg).await
    }
}

#[derive(Clone)]
pub struct WatcherHandle {
    validate_sender: mpsc::Sender<WatcherMessage>,
}

impl WatcherHandle {
    pub fn new() -> Self {
        let (sender, receiver) = mpsc::channel(8);
        let actor = WatcherCommunicationActor::new(receiver);
        tokio::spawn(run_my_actor(actor));

        Self {
            validate_sender: sender,
        }
    }

    pub async fn find(&self, id: IdentifierPrefix, digest: SelfAddressingIdentifier) -> Result<(), MessageboxError> {
        let (send, recv) = oneshot::channel();
        let msg = WatcherMessage::Find { identifier: id, digest };

        // Ignore send errors. If this send fails, so does the
        // recv.await below. There's no reason to check for the
        // same failure twice.
        let _ = self.validate_sender.send(msg).await;
		Ok(recv.await.expect("Err"))
    }
}

