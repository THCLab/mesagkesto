use std::path::Path;

use keri_sdk::keri_core::oobi::Role;
use keri_sdk::keri_core::query::reply_event::{ReplyEvent, SignedReply};
use keri_sdk::oobi_store::OobiStore;
use keri_sdk::IdentifierPrefix;
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, info};

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
    receiver: mpsc::Receiver<OobiMessage>,
    store: OobiStore,
}

impl OobiActor {
    fn new(receiver: mpsc::Receiver<OobiMessage>, oobi_db_path: &Path) -> Self {
        debug!(oobi_db_path = %oobi_db_path.display(), "Initializing OOBI actor");
        OobiActor {
            receiver,
            store: OobiStore::open(oobi_db_path).expect("Failed to open OOBI store"),
        }
    }
    fn handle_message(&mut self, msg: OobiMessage) {
        match msg {
            OobiMessage::GetLocation {
                endpoint_identifier,
                sender,
            } => {
                debug!(endpoint_id = %endpoint_identifier, "Getting location scheme");
                let loc_scheme = self.store.get_location(&endpoint_identifier);
                match loc_scheme.is_empty() {
                    false => {
                        debug!(endpoint_id = %endpoint_identifier, count = loc_scheme.len(), "Location schemes found")
                    }
                    true => debug!(endpoint_id = %endpoint_identifier, "No location schemes found"),
                }
                let _ = sender.send(loc_scheme);
            }
            OobiMessage::GetRole {
                controller_identifier,
                role,
                endpoint_identifier: _,
                sender,
            } => {
                debug!(cid = %controller_identifier, role = ?role, "Getting end role OOBI");
                let end_role = self
                    .store
                    .get_end_role(&controller_identifier, role.clone());
                match end_role.is_empty() {
                    false => {
                        debug!(cid = ?controller_identifier, role = ?role, count = end_role.len(), "End role OOBIs found")
                    }
                    true => {
                        debug!(cid = ?controller_identifier, role = ?role, "No end role OOBIs found")
                    }
                }
                let _ = sender.send(end_role);
            }
            OobiMessage::RegisterOobi { oobis, sender } => {
                let oobis_count = oobis.len();
                debug!(oobi_count = oobis_count, "Registering OOBIs");
                let success_count = self.store.register_many(&oobis);
                info!(
                    registered = success_count,
                    total = oobis_count,
                    "OOBI registration complete"
                );
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
        debug!("OOBI handle initialized");

        Self {
            oobi_sender: sender,
        }
    }

    pub async fn register(&self, replys: Vec<SignedReply>) -> u32 {
        debug!(oobi_count = replys.len(), "Registering OOBIs");
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
        debug!(id = %id, "Getting location scheme");
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
        debug!(cid = %controller_identifier, role = ?role, eid = %endpoint_identifier, "Getting end role OOBI");
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
