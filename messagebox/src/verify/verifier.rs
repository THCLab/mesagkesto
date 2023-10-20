use std::{
    collections::{HashMap, VecDeque},
    sync::Arc,
    time::Duration,
};

use controller::{
    config::ControllerConfig, error::ControllerError, identifier_controller::IdentifierController,
    BasicPrefix, Controller, EndRole, IdentifierPrefix, LocationScheme, Oobi,
};
use keri::{
    event_message::signature::{get_signatures, Nontransferable, Signature},
    oobi::Role,
    processor::event_storage::EventStorage,
    signer::Signer,
    transport::TransportError,
};
use tokio::{sync::Mutex, time::sleep};

use crate::MessageboxError;

use super::{
    reverify::ReverifyHandle, signer::SignerHandle, task::VerificationTask, VerifyMessage,
};

pub(crate) struct VerifyData {
    controller: IdentifierController,
    identifier: BasicPrefix,
    signer: SignerHandle,
    witnesses: Arc<Mutex<HashMap<IdentifierPrefix, Vec<BasicPrefix>>>>,
    reverify: ReverifyHandle,
    task_queue: Arc<Mutex<VecDeque<VerificationTask>>>,
}

impl VerifyData {
    pub async fn setup(
        db_path: &str,
        watcher_oobi: LocationScheme,
        seed: Option<String>,
    ) -> Result<Self, MessageboxError> {
        let signer = Arc::new(
            seed.map(|key| Signer::new_with_seed(&key.parse()?))
                .unwrap_or_else(|| Ok(Signer::new()))
                .unwrap(),
        );
        let signer = SignerHandle::new();

        let identifier = signer.public_key().await?;
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
            .sign(end_role.clone())
            .await
            .map_err(|e| MessageboxError::Keri)?;

        id.finalize_event(end_role.as_bytes(), signature)
            .await
            .unwrap();
        Ok(VerifyData {
            identifier,
            signer: signer.clone(),
            controller: id,
            witnesses: Arc::new(Mutex::new(HashMap::new())),
            reverify: ReverifyHandle::new(),
            task_queue: Arc::new(Mutex::new(VecDeque::new())),
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

    async fn has_oobi(&self, id: &IdentifierPrefix) -> bool {
        self.witnesses
            .lock()
            .await
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

    async fn ask_watcher(&self, id: &IdentifierPrefix) {
        // Ask watcher
        let mut query = vec![];

        for qry in self.controller.query_own_watchers(&id).unwrap() {
            let ssp = self
                .signer
                .sign(String::from_utf8(qry.encode().unwrap()).unwrap())
                .await
                .unwrap();
            query.push((qry.clone(), ssp));
        }

        let mut query_result = self.controller.finalize_query(query).await;
        println!("\nin ask watcher: {:?}", query_result);
        while matches!(
            query_result,
            Err(ControllerError::TransportError(
                TransportError::ResponseNotReady
            ))
        ) {
            sleep(Duration::from_secs(3)).await;
            let mut query = vec![];
            for qry in self.controller.query_own_watchers(&id).unwrap() {
                let ssp = self
                    .signer
                    .sign(String::from_utf8(qry.encode().unwrap()).unwrap())
                    .await
                    .unwrap();
                query.push((qry.clone(), ssp));
            }
            query_result = self.controller.finalize_query(query).await;
            println!("\nin ask watcher: {:?}", query_result);
            if query_result.is_ok() {
                self.task_queue
                    .lock()
                    .await
                    .push_back(VerificationTask::Reverify(id.clone()));
            }
        }
    }

    async fn verify_message(&self, message: String) -> Result<bool, MessageboxError> {
        let (data, signatures) = Self::split_cesr_stream(message.as_bytes());

        let ver_res = signatures
            .map(|sig| Self::verify(sig, &data, self.controller.source.storage.clone()))
            .collect::<Result<Vec<bool>, _>>();
        match ver_res {
            Ok(res) => Ok(res.into_iter().all(|a| a)),
            Err(MessageboxError::MissingEvent(id, said)) => {
                if self.has_oobi(&id).await {
                    // self.reverify.save(said.clone(), message.clone()).await.unwrap();
                    self.reverify
                        .save(id.clone(), message.clone())
                        .await
                        .unwrap();
                    // Ask watcher
                    {
                        self.task_queue
                            .lock()
                            .await
                            .push_back(VerificationTask::Find(id.clone()));
                    }
                    Err(MessageboxError::MissingEvent(id, said))
                } else {
                    Err(MessageboxError::MissingOobi)
                }
            }
            Err(MessageboxError::VerificationFailure) => Ok(false),
            Err(e) => Err(e),
        }
    }

    pub async fn handle_message(&self, msg: VerifyMessage) {
        match msg {
            VerifyMessage::Verify { message, sender } => {
                self.task_queue
                    .lock()
                    .await
                    .push_back(VerificationTask::Verify(message, sender))
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
                            let mut w = self.witnesses.lock().await;
                            match w.get_mut(cid) {
                                Some(s) => {
                                    s.push(bp.clone());
                                }
                                None => {
                                    w.insert(cid.clone(), vec![bp.clone()]);
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

    pub async fn handle_task(&self) {
        loop {
            let task = { self.task_queue.lock().await.pop_front() };
            if let Some(task) = task {
                match task {
                    VerificationTask::Verify(message, sender) => {
                        println!("\nHandle verify task");
                        let _ = sender.send(self.verify_message(message).await);
                    }
                    VerificationTask::Find(id) => {
                        println!("\nHandle  find task");
                        self.ask_watcher(&id).await
                    }
                    VerificationTask::Reverify(id) => {
                        let to_reverify = self.reverify.get(id.clone()).await.unwrap();
                        let res = self.verify_message(to_reverify).await.unwrap();
                        println!("\nHandle reverify task");
                    }
                };
            }
        }
    }
}
