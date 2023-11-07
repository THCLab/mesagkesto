use said::derivation::{HashFunction, HashFunctionCode};
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, oneshot};

use crate::{
    notifier::NotifyHandle, responses_store::ResponsesHandle, storage::StorageHandle,
    MessageboxError,
};

#[derive(Serialize, Deserialize)]
#[serde(tag = "t")]
#[serde(rename_all = "lowercase")]
pub enum MessageType {
    Qry(QueryArguments),
    Exn(ExchangeArguments),
}

#[derive(Serialize, Deserialize)]
#[serde(untagged)]
pub enum QueryArguments {
    ByDigest { i: String, d: Vec<String> },
    BySn { i: String, s: usize },
}

impl ToString for MessageType {
    fn to_string(&self) -> String {
        serde_json::to_string(&self).unwrap()
    }
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "r")]
#[serde(rename_all = "lowercase")]
pub enum ExchangeArguments {
    // Forward `a` to other identifier
    Fwd {
        i: String,
        a: String,
    },
    // Save firebase token (f) of given identifier (i)
    #[serde(rename = "/auth/f")]
    SetFirebase {
        i: String,
        f: String,
    },
}

pub enum ValidateMessage {
    Authenticate {
        message: String,
        // where to return result
        sender: oneshot::Sender<Result<Option<String>, MessageboxError>>,
    },
    ProcessAndSave {
        message: String,
    },
}

pub struct ValidateActor {
    // From where get messages
    receiver: mpsc::Receiver<ValidateMessage>,
    storage: StorageHandle,
    notify: NotifyHandle,
    responses_handle: ResponsesHandle,
}

impl ValidateActor {
    fn new(
        receiver: mpsc::Receiver<ValidateMessage>,
        storage: StorageHandle,
        notify: NotifyHandle,
        responses: ResponsesHandle,
    ) -> Self {
        ValidateActor {
            receiver,
            storage,
            notify,
            responses_handle: responses,
        }
    }

    async fn process(&self, message: &str) -> Result<Option<String>, MessageboxError> {
        if let Ok(parsed) = serde_json::from_str::<MessageType>(message) {
            match parsed {
                MessageType::Qry(qry) => match qry {
                    QueryArguments::ByDigest { i, d } => {
                        println!("Getting messages by digest {:?}", &d);
                        Ok(self.storage.get_by_digest(&i, d).await)
                    }
                    QueryArguments::BySn { i, s } => {
                        println!("Getting messages for {} from index {}", &i, s);
                        Ok(self.storage.get_by_index(&i, s).await)
                    }
                },
                MessageType::Exn(exn) => match exn {
                    ExchangeArguments::Fwd { i, a } => {
                        println!("Saving message {} for {}", &a, &i);
                        let digest_algo: HashFunction = (HashFunctionCode::Blake3_256).into();
                        let sai = digest_algo.derive(a.as_bytes()).to_string();
                        self.storage.save(i.clone(), a, sai).await.to_string();
                        Ok(None)
                    }
                    ExchangeArguments::SetFirebase { i, f: t } => {
                        self.notify.save_token(i, t).await;
                        Ok(None)
                    }
                },
            }
        } else {
            Err(MessageboxError::UnknownMessage(message.into()))
        }
    }

    async fn handle_message(&mut self, msg: ValidateMessage) {
        match msg {
            ValidateMessage::Authenticate { message, sender } => {
                let _ = sender.send(self.process(&message).await);
            }
            ValidateMessage::ProcessAndSave { message } => {
                println!("\nIn process and save: {}", message);
                let out = self.process(&message).await.unwrap();
                if let Some(to_save) = out {
                    let digest: said::SelfAddressingIdentifier =
                        HashFunction::from(HashFunctionCode::Blake3_256)
                            .derive(message.as_bytes());
                    self.responses_handle.save(to_save, digest).await;
                };
            }
        }
    }
}

async fn run_my_actor(mut actor: ValidateActor) {
    while let Some(msg) = actor.receiver.recv().await {
        actor.handle_message(msg).await
    }
}

#[derive(Clone)]
pub struct ValidateHandle {
    validate_sender: mpsc::Sender<ValidateMessage>,
}

impl ValidateHandle {
    pub fn new(
        storage_handle: StorageHandle,
        notify_handle: NotifyHandle,
        responses: ResponsesHandle,
    ) -> Self {
        let (sender, receiver) = mpsc::channel(8);
        let actor = ValidateActor::new(receiver, storage_handle, notify_handle, responses);
        tokio::spawn(run_my_actor(actor));

        Self {
            validate_sender: sender,
        }
    }

    pub async fn validate(&self, message: String) -> Result<Option<String>, MessageboxError> {
        let (send, recv) = oneshot::channel();
        let msg = ValidateMessage::Authenticate {
            message,
            sender: send,
        };

        // Ignore send errors. If this send fails, so does the
        // recv.await below. There's no reason to check for the
        // same failure twice.
        let _ = self.validate_sender.send(msg).await;
        match recv.await {
            Ok(res) => res,
            Err(_) => {
                println!("Actor task has been killed");
                Err(MessageboxError::KilledSender)
            }
        }
    }

    pub async fn process_and_save(&self, message: String) {
        let msg = ValidateMessage::ProcessAndSave { message };

        // Ignore send errors. If this send fails, so does the
        // recv.await below. There's no reason to check for the
        // same failure twice.
        let _ = self.validate_sender.send(msg).await;
    }
}
