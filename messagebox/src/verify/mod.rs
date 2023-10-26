mod reverify;
mod signer;
mod task;
mod verifier;

use std::{path::Path, sync::Arc};

use controller::LocationScheme;
use keri::event_message::signature::Signature;
use tokio::sync::{
    mpsc::{self},
    oneshot,
};

use crate::{validate::ValidateHandle, MessageboxError};

use self::verifier::VerifyData;

#[derive(Debug)]
pub enum VerifyMessage {
    Verify {
        message: String,
        signatures: Vec<Signature>,
        // where to return result
        sender: oneshot::Sender<Result<(), MessageboxError>>,
    },
    Oobi {
        message: String,
        // where to return result
        sender: oneshot::Sender<Result<bool, MessageboxError>>,
    },
}

pub struct VerifyActor {
    // From where get messages
    receiver: mpsc::Receiver<VerifyMessage>,
    data: Arc<VerifyData>,
}

impl VerifyActor {
    async fn setup(
        db_path: &Path,
        watcher_oobi: LocationScheme,
        seed: Option<String>,
        receiver: mpsc::Receiver<VerifyMessage>,
        validate_handle: ValidateHandle,
    ) -> Result<Self, MessageboxError> {
        let vd = VerifyData::setup(db_path, watcher_oobi, seed, validate_handle).await?;
        Ok(Self {
            receiver,
            data: Arc::new(vd),
        })
    }
}

async fn listen(vd: Arc<VerifyData>, mut receiver: mpsc::Receiver<VerifyMessage>) {
    while let Some(msg) = receiver.recv().await {
        vd.handle_message(msg).await;
    }
}

async fn run_my_actor(actor: VerifyActor) {
    let arc_data = actor.data.clone();
    tokio::spawn(async move {
        arc_data.clone().handle_task().await;
    });

    let arc_data = actor.data.clone();
    tokio::spawn(listen(arc_data, actor.receiver));
}

#[derive(Clone, Debug)]
pub struct VerifyHandle {
    validate_sender: mpsc::Sender<VerifyMessage>,
}

impl VerifyHandle {
    pub async fn new(db_path: &Path, validate_handle: ValidateHandle) -> Self {
        let (sender, receiver) = mpsc::channel(8);
        let watcher_oobi = serde_json::from_str(r#"{"eid":"BF2t2NPc1bwptY1hYV0YCib1JjQ11k9jtuaZemecPF5b","scheme":"http","url":"http://watcher.sandbox.argo.colossi.network/"}"#).unwrap();
        // let watcher_oobi = serde_json::from_str(r#"{"eid":"BF2t2NPc1bwptY1hYV0YCib1JjQ11k9jtuaZemecPF5b","scheme":"http","url":"http://localhost:3236/"}"#).unwrap();
        let actor = VerifyActor::setup(db_path, watcher_oobi, None, receiver, validate_handle)
            .await
            .unwrap();
        tokio::spawn(run_my_actor(actor));

        Self {
            validate_sender: sender,
        }
    }

    pub async fn resolve_oobi(&self, message: String) -> Result<(), MessageboxError> {
        let (send, recv) = oneshot::channel();

        let msg = VerifyMessage::Oobi {
            message,
            sender: send,
        };

        let _ = self.validate_sender.send(msg).await;
        match recv.await {
            Ok(res) => Ok(()),
            Err(_) => {
                println!("Actor task has been killed");
                Err(MessageboxError::KilledSender)
            }
        }
    }

    pub async fn verify(
        &self,
        message: &str,
        signatures: Vec<Signature>,
    ) -> Result<(), MessageboxError> {
        let (send, recv) = oneshot::channel();
        let msg = VerifyMessage::Verify {
            message: message.to_string(),
            signatures,
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

// #[cfg(test)]
// pub mod test {
//     use std::{sync::Arc, time::Duration};

//     use controller::{
//         config::ControllerConfig, identifier_controller::IdentifierController, BasicPrefix,
//         Controller, KeyManager, LocationScheme, SelfSigningPrefix,
//     };
//     use serde_json::json;
//     use tokio::time::sleep;

//     use crate::{verify::VerifyHandle, responses_store::ResponsesHandle, validate::ValidateHandle};

//     #[actix_web::test]
//     async fn test_verify_handle() {
//         use keri::signer::CryptoBox;

//         let cont = Arc::new(Controller::new(ControllerConfig::default()).unwrap());
//         let mut km1 = CryptoBox::new().unwrap();
//         let witness_oobi_st = r#"{"eid":"BJq7UABlttINuWJh1Xl2lkqZG4NTdUdqnbFJDa6ZyxCC","scheme":"http","url":"http://witness1.sandbox.argo.colossi.network/"}"#;
//         // let witness_oobi_st = r#"{"eid":"BJq7UABlttINuWJh1Xl2lkqZG4NTdUdqnbFJDa6ZyxCC","scheme":"http","url":"http://localhost:3232/"}"#;
//         let witness_oobi: LocationScheme = serde_json::from_str(witness_oobi_st).unwrap();
//         let witness_id: BasicPrefix = "BJq7UABlttINuWJh1Xl2lkqZG4NTdUdqnbFJDa6ZyxCC"
//             .parse()
//             .unwrap();

//         // Incept signer identifier and publish kel to witness.
//         let mut signing_identifier = {
//             let pk = BasicPrefix::Ed25519(km1.public_key());
//             let npk = BasicPrefix::Ed25519(km1.next_public_key());

//             let icp_event = cont
//                 .incept(vec![pk], vec![npk], vec![witness_oobi], 1)
//                 .await
//                 .unwrap();
//             let signature =
//                 SelfSigningPrefix::Ed25519Sha512(km1.sign(icp_event.as_bytes()).unwrap());

//             let incepted_identifier = cont
//                 .finalize_inception(icp_event.as_bytes(), &signature)
//                 .await
//                 .unwrap();
//             IdentifierController::new(incepted_identifier, cont.clone(), None)
//         };

//         signing_identifier.notify_witnesses().await.unwrap();

//         // Quering mailbox to get receipts
//         let query = signing_identifier
//             .query_mailbox(&signing_identifier.id, &[witness_id.clone()])
//             .unwrap();

//         // Query with wrong signature
//         {
//             let qry = query[0].clone();
//             let sig = SelfSigningPrefix::Ed25519Sha512(km1.sign(&qry.encode().unwrap()).unwrap());
//             signing_identifier
//                 .finalize_query(vec![(qry, sig)])
//                 .await
//                 .unwrap();
//         }

//         let rrr = signing_identifier.source.get_state(&signing_identifier.id);
//         assert!(rrr.is_ok());

//         let oobi_str = json!({"cid": &signing_identifier.id ,"role":"witness","eid":"BJq7UABlttINuWJh1Xl2lkqZG4NTdUdqnbFJDa6ZyxCC"}).to_string();

//         // let msg = r#"{"m":"hi there"}"#;
//         // let signature = SelfSigningPrefix::Ed25519Sha512(km1.sign(msg.as_bytes()).unwrap());
//         // let s = signing_identifier.sign_to_cesr(&msg, signature, 0).unwrap();
//         // println!("\ns: {}", s);
//         let rh = ResponsesHandle::new();
//         let vh = VerifyHandle::new(rh).await;

//         // assert!(matches!(
//         //     vh.verify(&s).await,
//         //     Err(MessageboxError::MissingOobi)
//         // ));
//         vh.resolve_oobi(witness_oobi_st.to_string()).await.unwrap();

//         // assert!(matches!(
//         //     vh.verify(&s).await,
//         //     Err(MessageboxError::MissingOobi)
//         // ));
//         vh.resolve_oobi(oobi_str.clone()).await.unwrap();

//         // let r = vh.verify(&s).await.unwrap();
//         // assert!(r);

//         // Rotate identifier and try to verify again
//         km1.rotate().unwrap();
//         let pk = BasicPrefix::Ed25519(km1.public_key());
//         let npk = BasicPrefix::Ed25519(km1.next_public_key());

//         let rot_event = signing_identifier
//             .rotate(vec![pk], vec![npk], vec![], vec![], 1)
//             .await
//             .unwrap();
//         let signature = SelfSigningPrefix::Ed25519Sha512(km1.sign(rot_event.as_bytes()).unwrap());
//         signing_identifier
//             .finalize_event(rot_event.as_bytes(), signature)
//             .await
//             .unwrap();

//         signing_identifier.notify_witnesses().await.unwrap();

//         // Quering mailbox to get receipts
//         let query = signing_identifier
//             .query_mailbox(&signing_identifier.id, &[witness_id.clone()])
//             .unwrap();

//         // Query with wrong signature
//         {
//             let qry = query[0].clone();
//             let sig = SelfSigningPrefix::Ed25519Sha512(km1.sign(&qry.encode().unwrap()).unwrap());
//             signing_identifier
//                 .finalize_query(vec![(qry, sig)])
//                 .await
//                 .unwrap();
//         }

//         // let oobi_str = json!({"cid": &signing_identifier.id ,"role":"witness","eid":"BJq7UABlttINuWJh1Xl2lkqZG4NTdUdqnbFJDa6ZyxCC"}).to_string();

//         let msg = r#"{"m":"hi there2"}"#;
//         let signature = SelfSigningPrefix::Ed25519Sha512(km1.sign(msg.as_bytes()).unwrap());
//         let s = signing_identifier.sign_to_cesr(&msg, signature, 0).unwrap();
//         println!("\ns: {}", s);
//         // vh.resolve_oobi(oobi_str).await.unwrap();
//         let r = vh.verify(&s).await;
//         dbg!(&r);
//         // assert!(matches!(r, Err(MessageboxError::MissingEvent(_, _))));
//         sleep(Duration::from_secs(5)).await;

//         // let r = vh.verify(&s).await.unwrap();
//         // assert!(r);
//     }
// }
