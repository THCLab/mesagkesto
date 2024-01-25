use keri_controller::{BasicPrefix, SelfSigningPrefix};
use keri_core::{keys::KeysError, signer::Signer};
use tokio::sync::{mpsc, oneshot};

use crate::MessageboxError;

#[derive(Debug)]
pub enum SignerMessage {
    Sign {
        data: String,
        sender: oneshot::Sender<Result<SelfSigningPrefix, KeysError>>,
    },
    PublicKey {
        sender: oneshot::Sender<BasicPrefix>,
    },
}

pub struct SignerActor {
    signer: Signer,
    // From where get messages
    receiver: mpsc::Receiver<SignerMessage>,
}

impl SignerActor {
    fn new(receiver: mpsc::Receiver<SignerMessage>) -> Self {
        SignerActor {
            signer: Signer::new(),
            receiver,
        }
    }

    fn new_with_seed(
        seed: &str,
        receiver: mpsc::Receiver<SignerMessage>,
    ) -> Result<Self, MessageboxError> {
        let signer = Signer::new_with_seed(
            &seed
                .parse()
                .map_err(|_e| MessageboxError::SeedParsingError)?,
        )
        .map_err(|_e| MessageboxError::SeedParsingError)?;
        Ok(SignerActor { signer, receiver })
    }

    async fn handle_message(&mut self, msg: SignerMessage) {
        match msg {
            SignerMessage::Sign { data, sender } => {
                let signature = self
                    .signer
                    .sign(data.as_bytes())
                    .map(SelfSigningPrefix::Ed25519Sha512);
                let _ = sender.send(signature);
            }
            SignerMessage::PublicKey { sender } => {
                let _ = sender.send(BasicPrefix::Ed25519NT(self.signer.public_key()));
            }
        }
    }
}

async fn run_my_actor(mut actor: SignerActor) {
    while let Some(msg) = actor.receiver.recv().await {
        actor.handle_message(msg).await
    }
}

#[derive(Clone)]
pub struct SignerHandle {
    validate_sender: mpsc::Sender<SignerMessage>,
}

impl SignerHandle {
    pub fn new() -> Self {
        let (sender, receiver) = mpsc::channel(8);
        let actor = SignerActor::new(receiver);
        tokio::spawn(run_my_actor(actor));

        Self {
            validate_sender: sender,
        }
    }

    pub fn new_with_seed(seed: &str) -> Result<Self, MessageboxError> {
        let (sender, receiver) = mpsc::channel(8);
        let actor = SignerActor::new_with_seed(seed, receiver)?;
        tokio::spawn(run_my_actor(actor));

        Ok(Self {
            validate_sender: sender,
        })
    }

    pub async fn sign(&self, message: String) -> Result<SelfSigningPrefix, MessageboxError> {
        let (send, recv) = oneshot::channel();
        let msg = SignerMessage::Sign {
            data: message,
            sender: send,
        };

        // Ignore send errors. If this send fails, so does the
        // recv.await below. There's no reason to check for the
        // same failure twice.
        let _ = self.validate_sender.send(msg).await;
        Ok(recv.await.expect("Err")?)
    }

    pub async fn public_key(&self) -> Result<BasicPrefix, MessageboxError> {
        let (send, recv) = oneshot::channel();
        let msg = SignerMessage::PublicKey { sender: send };

        // Ignore send errors. If this send fails, so does the
        // recv.await below. There's no reason to check for the
        // same failure twice.
        let _ = self.validate_sender.send(msg).await;
        Ok(recv.await.expect("Err"))
    }
}
