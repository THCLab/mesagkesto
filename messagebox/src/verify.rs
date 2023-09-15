use std::{path::Path, sync::Arc};

use controller::{
    config::ControllerConfig, error::ControllerError, identifier_controller::IdentifierController,
    BasicPrefix, Controller, LocationScheme, PrivateKey, SelfSigningPrefix, CryptoBox, KeyManager, IdentifierPrefix,
};
use keri::{
    event_message::signature::{get_signatures, Nontransferable, Signature},
    processor::event_storage::EventStorage,
    signer::Signer,
};
use tokio::sync::{mpsc, oneshot};

use crate::{MessageboxError};

pub enum VerifyMessage {
    Verify {
        message: String,
        // where to return result
        sender: oneshot::Sender<Result<bool, MessageboxError>>,
    },
}

pub struct VerifyActor {
    // From where get messages
    receiver: mpsc::Receiver<VerifyMessage>,
    controller: IdentifierController,
    identifier: BasicPrefix,
    signer: Arc<Signer>,
}

impl VerifyActor {
    async fn setup(
        db_path: &str,
        watcher_oobi: LocationScheme,
        seed: Option<String>,
        receiver: mpsc::Receiver<VerifyMessage>,
    ) -> Result<Self, MessageboxError> {
        let signer = Arc::new(
            seed.map(|key| Signer::new_with_seed(&key.parse()?))
                .unwrap_or_else(|| Ok(Signer::new()))
                .unwrap(),
        );

        let identifier = BasicPrefix::Ed25519(signer.public_key());
        let controller = Arc::new(
            Controller::new(ControllerConfig {
                db_path: db_path.into(),
                ..Default::default()
            })
            .map_err(|e| MessageboxError::Keri)?,
        );
        controller
            .resolve_oobi(controller::Oobi::Location(watcher_oobi.clone()))
            .await
            .unwrap();

        let id = IdentifierController::new(
            controller::IdentifierPrefix::Basic(identifier.clone()),
            controller.clone(),
            None,
        );
        let end_role = id
            .add_watcher(watcher_oobi.eid)
            .map_err(|e| MessageboxError::Keri)?;
        let signature = signer
            .sign(end_role.as_bytes())
            .map_err(|e| MessageboxError::Keri)?;
        let signature = SelfSigningPrefix::Ed25519Sha512(signature);

        id.finalize_event(end_role.as_bytes(), signature)
            .await
            .unwrap();
        Ok(VerifyActor {
            identifier,
            signer,
            receiver,
            controller: id,
        })
    }

    async fn missing_kel() {

    }

    fn verify(
        s: Signature,
        data: &[u8],
        storage: Arc<EventStorage>,
    ) -> Result<bool, MessageboxError> {
        match s {
            Signature::Transferable(sigd, sigs) => {
                let (kc, id) = match sigd {
                    keri::event_message::signature::SignerData::EventSeal(es) => if let Ok(r) = storage
                        .get_keys_at_event(&es.prefix, es.sn, &es.event_digest) {(r.map(|r| r), es.prefix)} else {(None, es.prefix)},
                    keri::event_message::signature::SignerData::LastEstablishment(id) => {
                        (storage.get_state(&id).unwrap().map(|e| e.current), id)
                    }
                    keri::event_message::signature::SignerData::JustSignatures => todo!(),
                };
                if let Some(k) = kc {
                    Ok(k.verify(data, &sigs).unwrap())
                } else {
                    Err(MessageboxError::MissingEvent(id))
                }
                
            }
            Signature::NonTransferable(Nontransferable::Couplet(couplets)) => Ok((couplets
                .iter()
                .all(|(id, sig)| id.verify(data, &sig).unwrap()))),
            Signature::NonTransferable(Nontransferable::Indexed(_sigs)) => {
                Err(MessageboxError::Keri)
            }
        }
    }

    async fn handle_message(&mut self, msg: VerifyMessage) {
        match msg {
            VerifyMessage::Verify { message, sender } => {
                let (_rest, parsed_data) = cesrox::parse(message.as_bytes()).unwrap();
                let data = match parsed_data.payload {
                    cesrox::payload::Payload::JSON(json) => json,
                    cesrox::payload::Payload::CBOR(_) => todo!(),
                    cesrox::payload::Payload::MGPK(_) => todo!(),
                };
                let signatures = parsed_data
                    .attachments
                    .into_iter()
                    .map(|g| get_signatures(g).unwrap())
                    .flatten();
                let ver_res = 
                    signatures.map(|sig| Self::verify(sig, &data, self.controller.source.storage.clone()))
					.collect::<Result<Vec<bool>,_>>();
                match ver_res {
                    Ok(res) => {
                        let _ = sender.send(Ok(res.into_iter().all(|a| a)));
                    },
                    Err(MessageboxError::MissingEvent(id)) => {
                        // check if oobi is in db
                        let oobis = self.controller.source.get_loc_schemas(&id);
                        match oobis {
                            Ok(oobi) => todo!(),
                            Err(ControllerError::UnknownIdentifierError) => {
                                let _ = sender.send(Err(MessageboxError::MissingOobi));
                            },
                            Err(_) => todo!(),
                        };
                    },
                    Err(MessageboxError::VerificationFailure) => {
                        let _ = sender.send(Ok(false));
                    },
                    Err(e) => {
                        println!("e: {}", e.to_string());
                        todo!()
                    },
                };
				
            }
        }
    }
}

async fn run_my_actor(mut actor: VerifyActor) {
    while let Some(msg) = actor.receiver.recv().await {
        actor.handle_message(msg).await;
    }
}

#[derive(Clone)]
pub struct VerifyHandle {
    validate_sender: mpsc::Sender<VerifyMessage>,
}

impl VerifyHandle {

    pub async fn new() -> Self {
        let (sender, receiver) = mpsc::channel(8);
		let watcher_oobi = serde_json::from_str(r#"{"eid":"BF2t2NPc1bwptY1hYV0YCib1JjQ11k9jtuaZemecPF5b","scheme":"http","url":"http://watcher.sandbox.argo.colossi.network/"}"#).unwrap();
        let actor = VerifyActor::setup("./bd", watcher_oobi, None, receiver).await.unwrap();
        tokio::spawn(run_my_actor(actor));

        Self {
            validate_sender: sender,
        }
    }

    pub async fn verify(&self, message: String) -> Result<bool, MessageboxError> {
        let (send, recv) = oneshot::channel();
        let msg = VerifyMessage::Verify {
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

#[actix_web::test]
async fn test_verify_handle() {
    let cont = Arc::new(Controller::new(ControllerConfig::default()).unwrap());
    let km1 = CryptoBox::new().unwrap();
    let km2 = CryptoBox::new().unwrap();

    let mut identifier1 = {
        let pk = BasicPrefix::Ed25519(km1.public_key());
        let npk = BasicPrefix::Ed25519(km1.next_public_key());

        let icp_event = cont.incept(vec![pk], vec![npk], vec![], 0).await.unwrap();
        let signature = SelfSigningPrefix::Ed25519Sha512(km1.sign(icp_event.as_bytes()).unwrap());

        let incepted_identifier = cont
            .finalize_inception(icp_event.as_bytes(), &signature)
            .await.unwrap();
        IdentifierController::new(incepted_identifier, cont.clone(), None)
    };
    identifier1.notify_witnesses().await.unwrap();
    let msg = r#"{"m":"hi there"}"#;
    let signature = SelfSigningPrefix::Ed25519Sha512(km1.sign(msg.as_bytes()).unwrap());
    let s = identifier1.sign_to_cesr(&msg, signature, 0).unwrap();
    println!("s: {}", s);

	let vh = VerifyHandle::new().await;
	let r = vh.verify(s).await.unwrap();
    println!("r: {}", r);
}