use said::derivation::{HashFunction, HashFunctionCode};
use tokio::sync::{mpsc, oneshot};

use crate::{notifier::NotifyHandle, storage::StorageHandle, messages::{MessageType, QueryRoute, ExchangeRoute}};


pub enum ValidateMessage {
    Authenticate {
        message: String,
        // where to return result
        sender: oneshot::Sender<Option<String>>,
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
                dbg!(&message);
                let parsed: MessageType = serde_json::from_str(&message).unwrap();
                let out = match parsed {
                    MessageType::Qry(qry) => match qry.get_route() {
                        QueryRoute::ByDigest { i, a } => {
                            println!("Getting messages by digest {:?}", &a);
                            self.storage.get_by_digest(&i, a).await
                        }
                        QueryRoute::BySn { i, s } => {
                            println!("Getting messages for {} from index {}", &i, s);
                            self.storage.get_by_index(&i, s).await
                        }
                    },
                    MessageType::Exn(exn) => match exn.get_route() {
                        ExchangeRoute::Fwd { i, a } => {
                            println!("Saving message {} for {}", &a, &i);
                            let digest_algo: HashFunction = (HashFunctionCode::Blake3_256).into();
                            let sai = digest_algo.derive(a.as_bytes()).to_string();
                            self.storage.save(i.clone(), a, sai).await.to_string();
                            None
                        }
                        ExchangeRoute::SetFirebase { i, f: t } => {
                            self.notify.save_token(i, t).await;
                            None
                        }
                    },
                };

                // The `let _ =` ignores any errors when sending.
                //
                // This can happen if the `select!` macro is used
                // to cancel waiting for the response.
                let _ = sender.send(out);
            }
        }
    }
}

async fn run_my_actor(mut actor: ValidateActor) {
    while let Some(msg) = actor.receiver.recv().await {
        actor.handle_message(msg).await;
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

    pub async fn validate(&self, message: String) -> Option<String> {
        let (send, recv) = oneshot::channel();
        let msg = ValidateMessage::Authenticate {
            message,
            sender: send,
        };

        // Ignore send errors. If this send fails, so does the
        // recv.await below. There's no reason to check for the
        // same failure twice.
        let _ = self.validate_sender.send(msg).await;
        recv.await.expect("Actor task has been killed")
    }
}
