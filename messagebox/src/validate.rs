use said::derivation::{HashFunction, HashFunctionCode};
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, oneshot};

use crate::{notifier::NotifyHandle, storage::StorageHandle, MessageboxError};

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
}

pub struct ValidateActor {
    // From where get messages
    receiver: mpsc::Receiver<ValidateMessage>,
    storage: StorageHandle,
    notify: NotifyHandle,
}

impl ValidateActor {
    fn new(
        receiver: mpsc::Receiver<ValidateMessage>,
        storage: StorageHandle,
        notify: NotifyHandle,
    ) -> Self {
        ValidateActor {
            receiver,
            storage,
            notify,
        }
    }
    async fn handle_message(&mut self, msg: ValidateMessage) {
        match msg {
            ValidateMessage::Authenticate { message, sender } => {
                if let Ok(parsed) = serde_json::from_str::<MessageType>(&message) {
                    let out = match parsed {
                        MessageType::Qry(qry) => match qry {
                            QueryArguments::ByDigest { i, d } => {
                                println!("Getting messages by digest {:?}", &d);
                                self.storage.get_by_digest(&i, d).await
                            }
                            QueryArguments::BySn { i, s } => {
                                println!("Getting messages for {} from index {}", &i, s);
                                self.storage.get_by_index(&i, s).await
                            }
                        },
                        MessageType::Exn(exn) => match exn {
                            ExchangeArguments::Fwd { i, a } => {
                                println!("Saving message {} for {}", &a, &i);
                                let digest_algo: HashFunction =
                                    (HashFunctionCode::Blake3_256).into();
                                let sai = digest_algo.derive(a.as_bytes()).to_string();
                                self.storage.save(i.clone(), a, sai).await.to_string();
                                None
                            }
                            ExchangeArguments::SetFirebase { i, f: t } => {
                                self.notify.save_token(i, t).await;
                                None
                            }
                        },
                    };
                    let _ = sender.send(Ok(out));
                } else {
                    let _ = sender.send(Err(MessageboxError::UnknownMessage(message.clone())));
                }
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
    pub fn new(storage_handle: StorageHandle, notify_handle: NotifyHandle) -> Self {
        let (sender, receiver) = mpsc::channel(8);
        let actor = ValidateActor::new(receiver, storage_handle, notify_handle);
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
}
