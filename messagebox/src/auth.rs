use std::path::Path;
use std::sync::Arc;

use chrono::Utc;
use dauthz_core::{CeremonyPurpose, Challenge, ChallengeResponse};
use dauthz_server::DauthzService;
use keri_core::prefix::{BasicPrefix, CesrPrimitive, SelfSigningPrefix};
use keri_core::signer::Signer;
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, oneshot};
use tracing::debug;

use crate::db::Db;
use crate::session::{Session, SessionStore};
use crate::MessageboxError;

/// The challenge payload that gets serialized to JSON inside the CESR stream.
/// Includes the DauthZ challenge fields plus the bound entity info.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengePayload {
    #[serde(flatten)]
    pub challenge: Challenge,
    pub entity_aid: String,
    pub entity_oobi: String,
}

pub enum AuthMessage {
    CreateChallenge {
        purpose: CeremonyPurpose,
        entity_aid: String,
        entity_oobi: String,
        sender: oneshot::Sender<Result<Vec<u8>, MessageboxError>>,
    },
    HandleResponse {
        nonce: String,
        verified: bool,
        sender: oneshot::Sender<Result<AuthResult, MessageboxError>>,
    },
    ValidateSession {
        token: String,
        sender: oneshot::Sender<Option<Session>>,
    },
    RevokeSession {
        token: String,
        sender: oneshot::Sender<bool>,
    },
}

#[derive(Debug, Clone)]
pub enum AuthResult {
    Registered { aid: String, account_id: String },
    Authenticated { session: Session },
    Invalid(String),
}

/// Stored alongside the DauthZ challenge to bind it to a specific entity.
struct BoundEntity {
    aid: String,
    #[allow(dead_code)]
    oobi: String,
}

struct AuthActor {
    receiver: mpsc::Receiver<AuthMessage>,
    dauthz: DauthzService,
    session_store: SessionStore,
    signer: Arc<Signer>,
    identifier: BasicPrefix,
    /// Nonce → bound entity info (stored when challenge is created)
    bound_entities: std::collections::HashMap<String, BoundEntity>,
}

impl AuthActor {
    fn new(
        receiver: mpsc::Receiver<AuthMessage>,
        dauthz: DauthzService,
        session_store: SessionStore,
        signer: Arc<Signer>,
        identifier: BasicPrefix,
    ) -> Self {
        Self {
            receiver,
            dauthz,
            session_store,
            signer,
            identifier,
            bound_entities: std::collections::HashMap::new(),
        }
    }

    /// Build a CESR stream: JSON payload + NontransReceiptCouples(identifier, signature)
    fn sign_to_cesr(&self, payload_json: &[u8]) -> Result<Vec<u8>, MessageboxError> {
        let sig = self
            .signer
            .sign(payload_json)
            .map_err(MessageboxError::SigningError)?;

        // Build the CESR attachment: NontransReceiptCouples group
        let cesr_sig = SelfSigningPrefix::Ed25519Sha512(sig);
        let couple_str = format!("{}{}", self.identifier.to_str(), cesr_sig.to_str());
        let group = format!(
            "-CAB{}",
            couple_str
        );

        let mut stream = payload_json.to_vec();
        stream.extend_from_slice(group.as_bytes());
        Ok(stream)
    }

    async fn handle_message(&mut self, msg: AuthMessage) {
        match msg {
            AuthMessage::CreateChallenge {
                purpose,
                entity_aid,
                entity_oobi,
                sender,
            } => {
                debug!(
                    entity_aid = %entity_aid,
                    purpose = ?purpose,
                    "Creating bound challenge"
                );
                let result = self
                    .dauthz
                    .create_challenge(purpose)
                    .map_err(|e| MessageboxError::AuthError(e.to_string()))
                    .and_then(|challenge| {
                        let payload = ChallengePayload {
                            challenge,
                            entity_aid: entity_aid.clone(),
                            entity_oobi: entity_oobi.clone(),
                        };
                        let payload_json = serde_json::to_vec(&payload)
                            .map_err(|e| MessageboxError::Unparsable(e.to_string()))?;

                        self.bound_entities.insert(
                            payload.challenge.nonce.clone(),
                            BoundEntity {
                                aid: entity_aid,
                                oobi: entity_oobi,
                            },
                        );

                        self.sign_to_cesr(&payload_json)
                    });
                let _ = sender.send(result);
            }
            AuthMessage::HandleResponse {
                nonce,
                verified,
                sender,
            } => {
                // Look up the bound entity for this nonce
                let bound = match self.bound_entities.remove(&nonce) {
                    Some(b) => b,
                    None => {
                        let _ = sender.send(Ok(AuthResult::Invalid(
                            "unknown or expired challenge nonce".to_string(),
                        )));
                        return;
                    }
                };

                // Build the ChallengeResponse that DauthZ expects
                let response = ChallengeResponse {
                    entity_aid: bound.aid.clone(),
                    entity_oobi: bound.oobi.clone(),
                    nonce: nonce.clone(),
                    signed_challenge: String::new(),
                };

                let result = match self.dauthz.handle_response(response, verified) {
                    Ok(dauthz_core::verification::VerificationResult::Registered {
                        aid,
                        account_id,
                    }) => Ok(AuthResult::Registered { aid, account_id }),
                    Ok(dauthz_core::verification::VerificationResult::Authenticated {
                        aid,
                        account_id,
                        session_token,
                    }) => {
                        let expires_at =
                            (Utc::now() + chrono::Duration::hours(1)).to_rfc3339();
                        let session = Session {
                            token: session_token,
                            account_id,
                            aid,
                            expires_at,
                        };
                        self.session_store.save(&session);
                        Ok(AuthResult::Authenticated { session })
                    }
                    Ok(dauthz_core::verification::VerificationResult::Invalid(reason)) => {
                        Ok(AuthResult::Invalid(reason))
                    }
                    Err(e) => Err(MessageboxError::AuthError(e.to_string())),
                };
                let _ = sender.send(result);
            }
            AuthMessage::ValidateSession { token, sender } => {
                let session = self.session_store.validate(&token);
                let _ = sender.send(session);
            }
            AuthMessage::RevokeSession { token, sender } => {
                let revoked = self.session_store.revoke(&token);
                let _ = sender.send(revoked);
            }
        }
    }
}

async fn run_auth_actor(mut actor: AuthActor) {
    while let Some(msg) = actor.receiver.recv().await {
        actor.handle_message(msg).await;
    }
}

#[derive(Clone)]
pub struct AuthHandle {
    sender: mpsc::Sender<AuthMessage>,
}

impl AuthHandle {
    pub fn new(
        dauthz_state_dir: &Path,
        service_aid: &str,
        service_oobi: &str,
        db: Db,
        signer: Arc<Signer>,
        identifier: BasicPrefix,
    ) -> Result<Self, MessageboxError> {
        let dauthz = DauthzService::new(dauthz_state_dir, service_aid, service_oobi)
            .map_err(|e| MessageboxError::AuthError(e.to_string()))?;
        let session_store = SessionStore::new(db);

        let (sender, receiver) = mpsc::channel(8);
        let actor = AuthActor::new(receiver, dauthz, session_store, signer, identifier);
        tokio::spawn(run_auth_actor(actor));

        Ok(Self { sender })
    }

    pub async fn create_challenge(
        &self,
        purpose: CeremonyPurpose,
        entity_aid: String,
        entity_oobi: String,
    ) -> Result<Vec<u8>, MessageboxError> {
        let (send, recv) = oneshot::channel();
        let msg = AuthMessage::CreateChallenge {
            purpose,
            entity_aid,
            entity_oobi,
            sender: send,
        };
        let _ = self.sender.send(msg).await;
        recv.await.map_err(|_| MessageboxError::KilledSender)?
    }

    pub async fn handle_response(
        &self,
        nonce: String,
        verified: bool,
    ) -> Result<AuthResult, MessageboxError> {
        let (send, recv) = oneshot::channel();
        let msg = AuthMessage::HandleResponse {
            nonce,
            verified,
            sender: send,
        };
        let _ = self.sender.send(msg).await;
        recv.await.map_err(|_| MessageboxError::KilledSender)?
    }

    pub async fn validate_session(&self, token: &str) -> Option<Session> {
        let (send, recv) = oneshot::channel();
        let msg = AuthMessage::ValidateSession {
            token: token.to_string(),
            sender: send,
        };
        let _ = self.sender.send(msg).await;
        recv.await.ok()?
    }

    pub async fn revoke_session(&self, token: &str) -> bool {
        let (send, recv) = oneshot::channel();
        let msg = AuthMessage::RevokeSession {
            token: token.to_string(),
            sender: send,
        };
        let _ = self.sender.send(msg).await;
        recv.await.unwrap_or(false)
    }
}
