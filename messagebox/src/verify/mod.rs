mod reverify;
mod watcher_communication;

use std::{collections::HashMap, sync::Arc, time::Duration};

use controller::{
    config::ControllerConfig, error::ControllerError, identifier_controller::IdentifierController,
    BasicPrefix, Controller, CryptoBox, EndRole, IdentifierPrefix, KeyManager, LocationScheme,
    Oobi, PrivateKey, SelfSigningPrefix,
};
use keri::{
    event_message::signature::{get_signatures, Nontransferable, Signature},
    oobi::Role,
    processor::event_storage::EventStorage,
    signer::Signer, actor::prelude::SelfAddressingIdentifier, transport::TransportError, query::query_event::QueryEvent,
};
use serde_json::json;
use tokio::{sync::{mpsc, oneshot}, time::sleep};

use crate::MessageboxError;

use self::reverify::ReverifyHandle;

#[derive(Debug)]
pub enum VerifyMessage {
    Verify {
        message: String,
        // where to return result
        sender: oneshot::Sender<Result<bool, MessageboxError>>,
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
    controller: IdentifierController,
    identifier: BasicPrefix,
    signer: Arc<Signer>,
    witnesses: HashMap<IdentifierPrefix, Vec<BasicPrefix>>,
    reverify: ReverifyHandle,
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
        let oobi = controller::Oobi::Location(watcher_oobi.clone());
        controller.resolve_oobi(oobi).await.unwrap();

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
            witnesses: HashMap::new(),
            reverify: ReverifyHandle::new(),
        })
    }

    fn verify(
        s: Signature,
        data: &[u8],
        storage: Arc<EventStorage>,
    ) -> Result<bool, MessageboxError> {
        match s {
            Signature::Transferable(sigd, sigs) => {
                let (kc, id, event_sai) = match sigd {
                    keri::event_message::signature::SignerData::EventSeal(es) => {
                        if let Ok(r) =
                            storage.get_keys_at_event(&es.prefix, es.sn, &es.event_digest)
                        {
                            (r.map(|r| r), es.prefix, Some(es.event_digest))
                        } else {
                            (None, es.prefix, Some(es.event_digest))
                        }
                    }
                    keri::event_message::signature::SignerData::LastEstablishment(id) => {
                        (storage.get_state(&id).unwrap().map(|e| e.current), id, None)
                    }
                    keri::event_message::signature::SignerData::JustSignatures => todo!(),
                };
                if let Some(k) = kc {
                    Ok(k.verify(data, &sigs).unwrap())
                } else {
                    Err(MessageboxError::MissingEvent(id, event_sai.unwrap()))
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

    fn split_cesr_stream(input: &[u8]) -> (Vec<u8>, impl Iterator<Item = Signature>) {
        let (_rest, parsed_data) = cesrox::parse(input).unwrap();
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
        (data, signatures)
    }

    fn has_oobi(&self, id: &IdentifierPrefix) -> bool {
        self.witnesses
            .get(&id)
            .map(|witnesses| {
                witnesses.into_iter().any(|eid| {
                    self.controller
                        .source
                        .get_loc_schemas(&IdentifierPrefix::Basic(eid.clone().clone()))
                        .map(|wits| !wits.is_empty())
                        .unwrap_or(false)
                })
            })
            .unwrap_or(false)
    }

    async fn ask_watcher(&mut self, id:&IdentifierPrefix) {
        // Ask watcher
        let query: Vec<(QueryEvent, SelfSigningPrefix)> = self.controller.query_own_watchers(id).unwrap()
            .iter()
            .map(|qry| {
                let signature = self.signer.sign(qry.encode().unwrap()).unwrap();
                let ssp = SelfSigningPrefix::Ed25519Sha512(signature);
                (qry.clone(), ssp)
            }).collect();
        println!("\nwatcher query: {:?}", &query);

        let rr = self.controller.finalize_query(query.clone()).await;
        let rr = match rr {
            Ok(rr) => rr,
            Err(e) => match e {
                ControllerError::DatabaseError(_) => todo!(),
                ControllerError::TransportError(TransportError::ResponseNotReady) => {
                    sleep(Duration::from_secs(10)).await;
                    self.controller.finalize_query(query).await.unwrap()
                },
                _ => todo!()
            },
        };
        let state = self.controller.source.get_state(&id);
        println!("\nid: {:?}", &id);
        println!("\nstate here: {:?}", state);

        println!("\nwatcher res: {:?}", rr);
    }

    async fn handle_message(&mut self, msg: VerifyMessage) {
        match msg {
            VerifyMessage::Verify { message, sender } => {
                let (data, signatures) = Self::split_cesr_stream(message.as_bytes());

                let ver_res = signatures
                    .map(|sig| Self::verify(sig, &data, self.controller.source.storage.clone()))
                    .collect::<Result<Vec<bool>, _>>();
                match ver_res {
                    Ok(res) => {
                        let _ = sender.send(Ok(res.into_iter().all(|a| a)));
                    }
                    Err(MessageboxError::MissingEvent(id, said)) => {
                        if self.has_oobi(&id) {
                            self.reverify.save(said.clone(), message).await.unwrap();
                            // Ask watcher
                            self.ask_watcher(&id).await;
                            let _ = sender.send(Err(MessageboxError::MissingEvent(id, said)));
                        } else {
                            let _ = sender.send(Err(MessageboxError::MissingOobi));
                        };
                    }
                    Err(MessageboxError::VerificationFailure) => {
                        let _ = sender.send(Ok(false));
                    }
                    Err(e) => {
                        let _ = sender.send(Err(e));
                    }
                };
            }
            VerifyMessage::Oobi { message, sender } => {
                let oobi: Oobi = serde_json::from_str(&message).unwrap();
                // Save witness oobi to be able to check, if we know it already!!!!
                match &oobi {
                    Oobi::EndRole(EndRole {
                        cid,
                        eid: IdentifierPrefix::Basic(bp),
                        role,
                    }) => {
                        if let Role::Witness = role {
                            let w = self.witnesses.get_mut(cid);
                            match w {
                                Some(s) => {
                                    s.push(bp.clone());
                                }
                                None => {
                                    self.witnesses.insert(cid.clone(), vec![bp.clone()]);
                                }
                            };
                        };
                    }
                    _ => {}
                };
                self.controller
                    .source
                    .resolve_oobi(oobi.clone())
                    .await
                    .unwrap();
                self.controller
                    .source
                    .send_oobi_to_watcher(&self.controller.id, &oobi)
                    .await
                    .unwrap();
                let _ = sender.send(Ok(true));
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
        // let watcher_oobi = serde_json::from_str(r#"{"eid":"BF2t2NPc1bwptY1hYV0YCib1JjQ11k9jtuaZemecPF5b","scheme":"http","url":"http://watcher.sandbox.argo.colossi.network/"}"#).unwrap();
        let watcher_oobi = serde_json::from_str(r#"{"eid":"BF2t2NPc1bwptY1hYV0YCib1JjQ11k9jtuaZemecPF5b","scheme":"http","url":"http://localhost:3236/"}"#).unwrap();
        let actor = VerifyActor::setup("./bb", watcher_oobi, None, receiver)
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

    pub async fn verify(&self, message: &str) -> Result<bool, MessageboxError> {
        let (send, recv) = oneshot::channel();
        let msg = VerifyMessage::Verify {
            message: message.to_string(),
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
    let mut km1 = CryptoBox::new().unwrap();
    // let witness_oobi: LocationScheme = serde_json::from_str(r#"{"eid":"BJq7UABlttINuWJh1Xl2lkqZG4NTdUdqnbFJDa6ZyxCC","scheme":"http","url":"http://witness1.sandbox.argo.colossi.network/"}"#).unwrap();
    let witness_oobi_st = r#"{"eid":"BJq7UABlttINuWJh1Xl2lkqZG4NTdUdqnbFJDa6ZyxCC","scheme":"http","url":"http://localhost:3232/"}"#;
    let witness_oobi: LocationScheme = serde_json::from_str(witness_oobi_st).unwrap();
    let witness_id: BasicPrefix = "BJq7UABlttINuWJh1Xl2lkqZG4NTdUdqnbFJDa6ZyxCC"
        .parse()
        .unwrap();

    // Incept signer identifier and publish kel to witness.
    let mut signing_identifier = {
        let pk = BasicPrefix::Ed25519(km1.public_key());
        let npk = BasicPrefix::Ed25519(km1.next_public_key());

        let icp_event = cont
            .incept(vec![pk], vec![npk], vec![witness_oobi], 1)
            .await
            .unwrap();
        let signature = SelfSigningPrefix::Ed25519Sha512(km1.sign(icp_event.as_bytes()).unwrap());

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
    let s = signing_identifier.sign_to_cesr(&msg, signature, 0).unwrap();
    println!("\ns: {}", s);

    let vh = VerifyHandle::new().await;

    assert!(matches!(
        vh.verify(&s).await,
        Err(MessageboxError::MissingOobi)
    ));
    vh.resolve_oobi(witness_oobi_st.to_string()).await.unwrap();

    assert!(matches!(vh.verify(&s).await, Err(MessageboxError::MissingOobi)));
    vh.resolve_oobi(oobi_str.clone()).await.unwrap();

    let r = vh.verify(&s).await.unwrap();
    println!("r: {}", r);

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

    // let oobi_str = json!({"cid": &signing_identifier.id ,"role":"witness","eid":"BJq7UABlttINuWJh1Xl2lkqZG4NTdUdqnbFJDa6ZyxCC"}).to_string();

    let msg = r#"{"m":"hi there2"}"#;
    let signature = SelfSigningPrefix::Ed25519Sha512(km1.sign(msg.as_bytes()).unwrap());
    let s = signing_identifier.sign_to_cesr(&msg, signature, 0).unwrap();
    println!("\ns: {}", s);
    // vh.resolve_oobi(oobi_str).await.unwrap();
    let r = vh.verify(&s).await;
    dbg!(&r);
    assert!(matches!(r, Err(MessageboxError::MissingEvent(_, _))));
    
    let r = vh.verify(&s).await.unwrap();
    assert!(r);
}
