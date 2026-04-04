use std::{collections::HashMap, path::Path, sync::Arc, time::Duration};

use keri_sdk::{
    BasicPrefix, EndRole, IdentifierPrefix, LocationScheme, Oobi, QueryResponse, Signature,
    WatcherResponseError,
};
use keri_sdk::keri_controller::{
    communication::SendingError,
    config::ControllerConfig,
    error::ControllerError,
    RedbController, RedbIdentifier,
};
use keri_sdk::keri_core::{
    actor::prelude::{HashFunction, HashFunctionCode},
    database::redb::RedbDatabase,
    event_message::signature::Nontransferable,
    oobi::Role,
    processor::event_storage::EventStorage,
    transport::TransportError,
};
use tokio::{
    sync::{
        mpsc::{self, Receiver, Sender},
        Mutex,
    },
    time::sleep,
};

use tracing::{debug, info, warn};

use crate::{validate::ValidateHandle, MessageboxError};

use super::{
    reverify::ReverifyHandle, signer::SignerHandle, task::VerificationTask, VerifyMessage,
};

pub(crate) struct VerifyData {
    controller: RedbIdentifier,
    signer: SignerHandle,
    witnesses: Arc<Mutex<HashMap<IdentifierPrefix, Vec<BasicPrefix>>>>,
    reverify: ReverifyHandle,
    task_sender: Sender<VerificationTask>,
    task_queue: Mutex<Receiver<VerificationTask>>,
    validate_handle: ValidateHandle,
}

impl VerifyData {
    pub async fn setup(
        db_path: &Path,
        watcher_oobi: LocationScheme,
        seed: Option<String>,
        validate_handle: ValidateHandle,
    ) -> Result<Self, MessageboxError> {
        debug!(db_path = %db_path.display(), watcher_oobi = ?watcher_oobi, "Initializing verify data");
        let signer = match seed {
            Some(seed) => SignerHandle::new_with_seed(&seed)?,
            None => SignerHandle::new(),
        };

        let identifier = signer.public_key().await?;
        debug!(identifier = ?identifier, "Verifier identifier obtained");

        let controller = Arc::new(RedbController::new(ControllerConfig {
            db_path: db_path.into(),
            ..Default::default()
        })?);
        let oobi = Oobi::Location(watcher_oobi.clone());

        let id = RedbIdentifier::new(
            IdentifierPrefix::Basic(identifier.clone()),
            None,
            controller.known_events.clone(),
            controller.communication.clone(),
        );

        debug!("Resolving watcher OOBI");
        id.resolve_oobi(&oobi)
            .await
            .map_err(ControllerError::from)?;
        debug!("Adding watcher to identifier");
        let end_role = id
            .add_watcher(watcher_oobi.eid)
            .map_err(ControllerError::from)?;
        let signature = signer.sign(end_role.clone()).await?;
        id.finalize_add_watcher(end_role.as_bytes(), signature)
            .await
            .map_err(ControllerError::from)?;
        let (task_sender, task_receiver) = mpsc::channel(20);
        info!("Verify data initialized successfully");
        Ok(VerifyData {
            signer: signer.clone(),
            controller: id,
            witnesses: Arc::new(Mutex::new(HashMap::new())),
            reverify: ReverifyHandle::new(),
            task_queue: Mutex::new(task_receiver),
            task_sender,
            validate_handle,
        })
    }

    /// Verify a signature and return (valid, sender_id).
    fn verify(
        s: &Signature,
        data: &[u8],
        storage: Arc<EventStorage<RedbDatabase>>,
    ) -> Result<(bool, Option<IdentifierPrefix>), MessageboxError> {
        match s {
            Signature::Transferable(sigd, sigs) => {
                let (kc, id, event_sai) = match sigd {
                    keri_sdk::keri_core::event_message::signature::SignerData::EventSeal(es) => {
                        if let Ok(r) =
                            storage.get_keys_at_event(&es.prefix, es.sn, &es.event_digest())
                        {
                            (r, es.prefix.clone(), Some(es.event_digest()))
                        } else {
                            (None, es.prefix.clone(), Some(es.event_digest()))
                        }
                    }
                    keri_sdk::keri_core::event_message::signature::SignerData::LastEstablishment(id) => {
                        (storage.get_state(id).map(|e| e.current), id.clone(), None)
                    }
                    keri_sdk::keri_core::event_message::signature::SignerData::JustSignatures => todo!(),
                };
                if let Some(k) = kc {
                    Ok((k.verify(data, sigs).unwrap(), Some(id)))
                } else {
                    Err(MessageboxError::MissingEvent(id, event_sai.unwrap()))
                }
            }
            Signature::NonTransferable(Nontransferable::Couplet(couplets)) => Ok((couplets
                .iter()
                .all(|(id, sig)| id.verify(data, sig).unwrap()), None)),
            Signature::NonTransferable(Nontransferable::Indexed(_sigs)) => {
                todo!()
            }
        }
    }

    async fn has_oobi(&self, id: &IdentifierPrefix) -> bool {
        self.witnesses
            .lock()
            .await
            .get(id)
            .map(|witnesses| {
                witnesses.iter().any(|eid| {
                    self.controller
                        .known_events
                        .get_loc_schemas(&IdentifierPrefix::Basic(eid.clone()))
                        .map(|wits| !wits.is_empty())
                        .unwrap_or(false)
                })
            })
            .unwrap_or(false)
    }

    async fn ask_watcher(&self, id: &IdentifierPrefix) {
        loop {
            let watchers = match self.controller.watchers() {
                Ok(w) => w,
                Err(_) => return,
            };
            if watchers.is_empty() {
                return;
            }

            let mut query = vec![];
            for watcher in watchers {
                let qry = match self.controller.query_full_log(id, watcher) {
                    Ok(q) => q,
                    Err(_) => continue,
                };
                let ssp = self
                    .signer
                    .sign(String::from_utf8(qry.encode().unwrap()).unwrap())
                    .await
                    .unwrap();
                query.push((qry.clone(), ssp));
            }

            let (resp, errs) = self.controller.finalize_query(query).await;
            let should_retry = errs.iter().any(|e| {
                matches!(
                    e,
                    WatcherResponseError::SendingError(SendingError::TransportError(
                        TransportError::NetworkError(_)
                            | TransportError::EmptyResponse
                            | TransportError::InvalidResponse(_)
                            | TransportError::UnknownError(_)
                    ))
                )
            });

            if resp == QueryResponse::Updates {
                let _ = self
                    .task_sender
                    .send(VerificationTask::Reverify(id.clone()))
                    .await;
            }

            if should_retry {
                sleep(Duration::from_secs(3)).await;
                continue;
            }

            if !errs.is_empty() {
                warn!(errors = ?errs, "Ask watcher errors");
            }
            break;
        }
    }

    /// Verify message signatures and return the sender's AID if available.
    async fn verify_message(
        &self,
        message: &str,
        signatures: Vec<Signature>,
    ) -> Result<Option<IdentifierPrefix>, MessageboxError> {
        debug!(
            message_len = message.len(),
            sig_count = signatures.len(),
            "Verifying message"
        );

        let ver_res = signatures
            .iter()
            .map(|sig| {
                Self::verify(
                    sig,
                    message.as_bytes(),
                    self.controller.known_events.storage.clone(),
                )
            })
            .collect::<Result<Vec<(bool, Option<IdentifierPrefix>)>, _>>();
        debug!(result = ?ver_res, "Signature verification result");

        match ver_res {
            Ok(res) => {
                let all_valid = res.iter().all(|(valid, _)| *valid);
                let sender_id = res.iter().find_map(|(_, id)| id.clone());
                if all_valid {
                    info!("Message verified successfully");
                    Ok(sender_id)
                } else {
                    warn!("Message verification failed: some signatures invalid");
                    Err(MessageboxError::VerificationFailure)
                }
            }
            Err(MessageboxError::MissingEvent(id, _said)) => {
                debug!(id = %id, "Missing event, checking OOBI");
                if self.has_oobi(&id).await {
                    info!(id = %id, "Saving message for re-verification after KEL update");
                    self.reverify
                        .save(id.clone(), message.to_string(), signatures)
                        .await
                        .unwrap();
                    // Ask watcher
                    {
                        let _ = self
                            .task_sender
                            .send(VerificationTask::Find(id.clone()))
                            .await;
                    }

                    let digest: keri_sdk::SelfAddressingIdentifier =
                        HashFunction::from(HashFunctionCode::Blake3_256).derive(message.as_bytes());
                    warn!(id = %id, digest = %digest, "Response not ready, waiting for KEL update");
                    Err(MessageboxError::ResponseNotReady(digest))
                } else {
                    warn!(id = %id, "Missing OOBI for identifier, cannot verify");
                    Err(MessageboxError::MissingOobi)
                }
            }
            Err(e) => {
                warn!(error = %e, "Message verification error");
                Err(e)
            }
        }
    }

    async fn handle_oobi(&self, oobi_str: &str) -> Result<(), MessageboxError> {
        debug!(oobi = %oobi_str, "Processing OOBI");
        let oobi: Oobi =
            serde_json::from_str(oobi_str).map_err(|_| MessageboxError::OobiParsingError)?;

        debug!("Saving witness OOBI if present");
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
                            if !s.contains(bp) {
                                s.push(bp.clone());
                                debug!(cid = ?cid, eid = ?bp, "Added witness to existing list");
                            } else {
                                debug!(cid = ?cid, eid = ?bp, "Witness already in list");
                            }
                        }
                        None => {
                            w.insert(cid.clone(), vec![bp.clone()]);
                            debug!(cid = ?cid, eid = ?bp, "Created new witness list");
                        }
                    };
                } else {
                    debug!(role = ?role, "OOBI is not a witness role, skipping");
                };
            }
            _ => {
                debug!("OOBI is not an EndRole type");
            }
        };

        debug!("Resolving OOBI through controller");
        self.controller
            .resolve_oobi(&oobi)
            .await
            .map_err(ControllerError::from)
            .map_err(MessageboxError::OobiError)?;

        debug!("Sending OOBI to watcher");
        self.controller
            .send_oobi_to_watcher(self.controller.id(), &oobi)
            .await
            .map_err(MessageboxError::OobiError)?;

        info!(oobi = %oobi_str, "OOBI processed successfully");
        Ok(())
    }

    pub async fn handle_message(&self, msg: VerifyMessage) {
        match msg {
            VerifyMessage::Verify {
                message,
                signatures,
                sender,
            } => {
                let _ = self
                    .task_sender
                    .send(VerificationTask::Verify(message, signatures, sender))
                    .await;
            }
            VerifyMessage::Oobi { message, sender } => {
                let _ = sender.send(self.handle_oobi(&message).await);
            }
        }
    }

    pub async fn handle_task(&self) {
        debug!("Verification task handler started");
        loop {
            let mut queue = self.task_queue.lock().await;
            if let Some(task) = queue.recv().await {
                match task {
                    VerificationTask::Verify(message, signature, sender) => {
                        debug!(
                            message_len = message.len(),
                            sig_count = signature.len(),
                            "Handle verify task"
                        );
                        let _ = sender.send(self.verify_message(&message, signature).await);
                    }
                    VerificationTask::Find(id) => {
                        debug!(id = %id, "Handle find task");
                        info!(id = %id, "Querying watcher for identifier");
                        self.ask_watcher(&id).await
                    }
                    VerificationTask::Reverify(id) => {
                        debug!(id = %id, "Handle reverify task");
                        info!(id = %id, "Re-verifying message after KEL update");
                        let (data, signatures) = self.reverify.get(id.clone()).await.unwrap();
                        let message = String::from_utf8(data).unwrap();
                        match self.verify_message(&message, signatures).await {
                            Ok(_) => {
                                info!(id = %id, "Re-verification successful, processing message");
                                self.validate_handle.process_and_save(message).await;
                            }
                            Err(e) => {
                                warn!(id = %id, error = %e, "Re-verification failed");
                            }
                        }
                    }
                };
            }
        }
    }
}
