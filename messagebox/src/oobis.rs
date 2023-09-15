use std::path::Path;

use keri::oobi::OobiManager;
use keri::query::reply_event::{ReplyEvent, SignedReply};
use keri::{oobi::Role, prefix::IdentifierPrefix};
use tokio::sync::{mpsc, oneshot};

pub enum OobiMessage {
    GetLocation {
        endpoint_identifier: IdentifierPrefix,
        // where to return result
        sender: oneshot::Sender<Vec<ReplyEvent>>,
    },
    GetRole {
        controller_identifier: IdentifierPrefix,
        role: Role,
        endpoint_identifier: IdentifierPrefix,
        // where to return result
        sender: oneshot::Sender<Vec<SignedReply>>,
    },
    RegisterOobi {
        oobis: Vec<SignedReply>,
        // where to return result
        sender: oneshot::Sender<u32>,
    },
}

pub struct OobiActor {
    // From where get messages
    receiver: mpsc::Receiver<OobiMessage>,
    pub oobi_manager: OobiManager,
}

impl OobiActor {
    fn new(receiver: mpsc::Receiver<OobiMessage>, oobi_db_path: &Path) -> Self {
        OobiActor {
            receiver,
            oobi_manager: OobiManager::new(oobi_db_path),
        }
    }
    fn handle_message(&mut self, msg: OobiMessage) {
        match msg {
            OobiMessage::GetLocation {
                endpoint_identifier,
                sender,
            } => {
                let loc_scheme = self
                    .oobi_manager
                    .get_loc_scheme(&endpoint_identifier)
                    .unwrap()
                    .unwrap_or_default();
                let _ = sender.send(loc_scheme);
            }
            OobiMessage::GetRole {
                controller_identifier,
                role,
                endpoint_identifier: _,
                sender,
            } => {
                let end_role = self
                    .oobi_manager
                    .get_end_role(&controller_identifier, role)
                    .unwrap();
                let _ = sender.send(end_role);
            }
            OobiMessage::RegisterOobi { oobis, sender } => {
                for reply in oobis {
                    self.oobi_manager.process_oobi(&reply).unwrap();
                }
                let _ = sender.send(1);
            }
        }
    }
}

async fn run_my_actor(mut actor: OobiActor) {
    while let Some(msg) = actor.receiver.recv().await {
        actor.handle_message(msg);
    }
}

#[derive(Clone)]
pub struct OobiHandle {
    oobi_sender: mpsc::Sender<OobiMessage>,
}

impl OobiHandle {
    pub fn new(db_path: &Path) -> Self {
        let (sender, receiver) = mpsc::channel(8);
        let actor = OobiActor::new(receiver, db_path);
        tokio::spawn(run_my_actor(actor));

        Self {
            oobi_sender: sender,
        }
    }

    pub async fn register(&self, replys: Vec<SignedReply>) -> u32 {
        let (send, recv) = oneshot::channel();

        let msg = OobiMessage::RegisterOobi {
            oobis: replys,
            sender: send,
        };
        // Ignore send errors. If this send fails, so does the
        // recv.await below. There's no reason to check for the
        // same failure twice.
        let _ = self.oobi_sender.send(msg).await;
        recv.await.expect("Actor task has been killed")
    }

    pub async fn get_location(&self, id: IdentifierPrefix) -> Option<Vec<ReplyEvent>> {
        let (send, recv) = oneshot::channel();
        let msg = OobiMessage::GetLocation {
            endpoint_identifier: id,
            sender: send,
        };

        // Ignore send errors. If this send fails, so does the
        // recv.await below. There's no reason to check for the
        // same failure twice.
        let _ = self.oobi_sender.send(msg).await;
        Some(recv.await.expect("Actor task has been killed"))
    }

    pub async fn get_role_oobi(
        &self,
        controller_identifier: IdentifierPrefix,
        role: Role,
        endpoint_identifier: IdentifierPrefix,
    ) -> Option<Vec<SignedReply>> {
        let (sender, recv) = oneshot::channel();
        let msg = OobiMessage::GetRole {
            controller_identifier,
            role,
            endpoint_identifier,
            sender,
        };

        // Ignore send errors. If this send fails, so does the
        // recv.await below. There's no reason to check for the
        // same failure twice.
        let _ = self.oobi_sender.send(msg).await;
        Some(recv.await.expect("Actor task has been killed"))
    }
}
