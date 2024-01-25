mod reverify;
mod signer;
mod task;
mod verifier;

use std::{path::Path, sync::Arc};

use keri_controller::LocationScheme;
use keri_core::event_message::signature::Signature;
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
        sender: oneshot::Sender<Result<(), MessageboxError>>,
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
    pub async fn new(
        db_path: &Path,
        watcher_oobi: LocationScheme,
        validate_handle: ValidateHandle,
    ) -> Result<Self, MessageboxError> {
        let (sender, receiver) = mpsc::channel(8);
        let actor =
            VerifyActor::setup(db_path, watcher_oobi, None, receiver, validate_handle).await?;
        tokio::spawn(run_my_actor(actor));

        Ok(Self {
            validate_sender: sender,
        })
    }

    pub async fn resolve_oobi(&self, message: String) -> Result<(), MessageboxError> {
        let (send, recv) = oneshot::channel();

        let msg = VerifyMessage::Oobi {
            message,
            sender: send,
        };

        let _ = self.validate_sender.send(msg).await;
        match recv.await {
            Ok(res) => res,
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

#[cfg(test)]
pub mod test {
    use std::{sync::Arc, time::Duration};

    use keri_controller::{
        config::ControllerConfig, identifier_controller::IdentifierController, BasicPrefix,
        Controller, KeyManager, LocationScheme, SelfSigningPrefix,
    };
    use serde_json::json;
    use tempfile::Builder;
    use tokio::time::sleep;

    use crate::{
        forward_message, notifier::NotifyHandle, responses_store::ResponsesHandle,
        storage::StorageHandle, validate::ValidateHandle, verify::VerifyHandle, MessageboxError,
    };

    #[actix_web::test]
    async fn test_verify_handle() -> Result<(), MessageboxError> {
        use keri_core::signer::CryptoBox;
        let root = Builder::new().prefix("test-db").tempdir().unwrap();
        let cont = Arc::new(
            Controller::new(ControllerConfig {
                db_path: root.path().into(),
                ..ControllerConfig::default()
            })
            .unwrap(),
        );
        let mut km1 = CryptoBox::new().unwrap();
        let witness_oobi_st = r#"{"eid":"BJq7UABlttINuWJh1Xl2lkqZG4NTdUdqnbFJDa6ZyxCC","scheme":"http","url":"http://witness1.sandbox.argo.colossi.network/"}"#;
        // let witness_oobi_st = r#"{"eid":"BJq7UABlttINuWJh1Xl2lkqZG4NTdUdqnbFJDa6ZyxCC","scheme":"http","url":"http://localhost:3232/"}"#;
        let witness_oobi: LocationScheme = serde_json::from_str(witness_oobi_st).unwrap();
        let witness_id: BasicPrefix = "BJq7UABlttINuWJh1Xl2lkqZG4NTdUdqnbFJDa6ZyxCC"
            .parse()
            .unwrap();

        // Incept signer identifier and publish kel to witness.
        let signing_identifier = {
            let pk = BasicPrefix::Ed25519(km1.public_key());
            let npk = BasicPrefix::Ed25519(km1.next_public_key());

            let icp_event = cont
                .incept(vec![pk], vec![npk], vec![witness_oobi], 1)
                .await
                .unwrap();
            let signature =
                SelfSigningPrefix::Ed25519Sha512(km1.sign(icp_event.as_bytes()).unwrap());

            let incepted_identifier = cont
                .finalize_inception(icp_event.as_bytes(), &signature)
                .await
                .unwrap();
            IdentifierController::new(incepted_identifier, cont.clone(), None)
        };

        signing_identifier.notify_witnesses().await.unwrap();

        // Quering mailbox to get receipts
        let query = signing_identifier
            .query_mailbox(&signing_identifier.id, &[witness_id.clone()])
            .unwrap();

        // Query with wrong signature
        {
            let qry = query[0].clone();
            let sig = SelfSigningPrefix::Ed25519Sha512(km1.sign(&qry.encode().unwrap()).unwrap());
            signing_identifier
                .finalize_query(vec![(qry, sig)])
                .await
                .unwrap();
        }

        let rrr = signing_identifier.source.get_state(&signing_identifier.id);
        assert!(rrr.is_ok());

        let oobi_str = json!({"cid": &signing_identifier.id ,"role":"witness","eid":"BJq7UABlttINuWJh1Xl2lkqZG4NTdUdqnbFJDa6ZyxCC"}).to_string();

        let msg = r#"{"m":"hi there"}"#;
        let signature = SelfSigningPrefix::Ed25519Sha512(km1.sign(msg.as_bytes()).unwrap());
        let signature = signing_identifier.sign(signature, 0).unwrap();

        let notify_handle =
            NotifyHandle::new("AAAAky1v068:APA91bHHpGtP6M5h3ICFc9AzY35MrkTmjwblkLlEJ1C0yvkrUu7KDkmkXMzPq2q-0o1l49fKxOeDQaKIkZTTEAIX3Jd45j6KNtSempYqop4Psitvz2Ng7iBz-IeS1SGEs1GpnWseJlpP".to_string());
        let storage_handle = StorageHandle::new(notify_handle.clone());
        let response_handle = ResponsesHandle::new();
        let validator_handle = ValidateHandle::new(
            storage_handle.clone(),
            notify_handle,
            response_handle.clone(),
        );
        let watcher_oobi = serde_json::from_str(r#"{"eid":"BF2t2NPc1bwptY1hYV0YCib1JjQ11k9jtuaZemecPF5b","scheme":"http","url":"http://localhost:3236/"}"#).unwrap();
        let root = Builder::new().prefix("test-db2").tempdir().unwrap();
        let vh = VerifyHandle::new(root.path(), watcher_oobi, validator_handle).await?;

        assert!(matches!(
            vh.verify(&msg, vec![signature.clone()]).await,
            Err(MessageboxError::MissingOobi)
        ));
        vh.resolve_oobi(witness_oobi_st.to_string()).await.unwrap();

        assert!(matches!(
            vh.verify(&msg, vec![signature.clone()]).await,
            Err(MessageboxError::MissingOobi)
        ));
        vh.resolve_oobi(oobi_str.clone()).await.unwrap();

        let r = vh.verify(&msg, vec![signature]).await;
        assert!(r.is_ok());

        // Rotate identifier and try to verify again
        km1.rotate().unwrap();
        let pk = BasicPrefix::Ed25519(km1.public_key());
        let npk = BasicPrefix::Ed25519(km1.next_public_key());

        let rot_event = signing_identifier
            .rotate(vec![pk], vec![npk], vec![], vec![], 1)
            .await
            .unwrap();
        let signature = SelfSigningPrefix::Ed25519Sha512(km1.sign(rot_event.as_bytes()).unwrap());
        signing_identifier
            .finalize_event(rot_event.as_bytes(), signature)
            .await
            .unwrap();

        signing_identifier.notify_witnesses().await.unwrap();

        // Querying mailbox to get receipts
        let query = signing_identifier
            .query_mailbox(&signing_identifier.id, &[witness_id.clone()])
            .unwrap();

        // Query with wrong signature
        {
            let qry = query[0].clone();
            let sig = SelfSigningPrefix::Ed25519Sha512(km1.sign(&qry.encode().unwrap()).unwrap());
            signing_identifier
                .finalize_query(vec![(qry, sig)])
                .await
                .unwrap();
        }

        // let oobi_str = json!({"cid": &signing_identifier.id ,"role":"witness","eid":"BJq7UABlttINuWJh1Xl2lkqZG4NTdUdqnbFJDa6ZyxCC"}).to_string();

        let msg = r#"{"m":"hi there2"}"#;
        let exn = forward_message(signing_identifier.id.to_string(), msg.to_string());
        let signature =
            SelfSigningPrefix::Ed25519Sha512(km1.sign(exn.to_string().as_bytes()).unwrap());
        let signature = signing_identifier.sign(signature, 0).unwrap();
        // vh.resolve_oobi(oobi_str).await.unwrap();
        let r = vh.verify(&exn.to_string(), vec![signature.clone()]).await;
        dbg!(&r);
        assert!(matches!(r, Err(MessageboxError::ResponseNotReady(_))));
        sleep(Duration::from_secs(5)).await;

        let r = vh.verify(&exn.to_string(), vec![signature]).await;
        assert!(r.is_ok());
        Ok(())
    }
}
