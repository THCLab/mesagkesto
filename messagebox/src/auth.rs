use std::path::Path;

use chrono::Utc;
use dauthz_core::{CeremonyPurpose, Challenge, ChallengeResponse};
use dauthz_server::DauthzService;
use tokio::sync::{mpsc, oneshot};

use crate::db::Db;
use crate::session::{Session, SessionStore};
use crate::MessageboxError;

pub enum AuthMessage {
    CreateChallenge {
        purpose: CeremonyPurpose,
        sender: oneshot::Sender<Result<Challenge, MessageboxError>>,
    },
    HandleResponse {
        response: ChallengeResponse,
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

struct AuthActor {
    receiver: mpsc::Receiver<AuthMessage>,
    dauthz: DauthzService,
    session_store: SessionStore,
}

impl AuthActor {
    fn new(
        receiver: mpsc::Receiver<AuthMessage>,
        dauthz: DauthzService,
        session_store: SessionStore,
    ) -> Self {
        Self {
            receiver,
            dauthz,
            session_store,
        }
    }

    async fn handle_message(&mut self, msg: AuthMessage) {
        match msg {
            AuthMessage::CreateChallenge { purpose, sender } => {
                let result = self
                    .dauthz
                    .create_challenge(purpose)
                    .map_err(|e| MessageboxError::AuthError(e.to_string()));
                let _ = sender.send(result);
            }
            AuthMessage::HandleResponse {
                response,
                verified,
                sender,
            } => {
                let result = match self.dauthz.handle_response(response, verified) {
                    Ok(dauthz_core::verification::VerificationResult::Registered { aid, account_id }) => {
                        Ok(AuthResult::Registered { aid, account_id })
                    }
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
    ) -> Result<Self, MessageboxError> {
        let dauthz = DauthzService::new(dauthz_state_dir, service_aid, service_oobi)
            .map_err(|e| MessageboxError::AuthError(e.to_string()))?;
        let session_store = SessionStore::new(db);

        let (sender, receiver) = mpsc::channel(8);
        let actor = AuthActor::new(receiver, dauthz, session_store);
        tokio::spawn(run_auth_actor(actor));

        Ok(Self { sender })
    }

    pub async fn create_challenge(
        &self,
        purpose: CeremonyPurpose,
    ) -> Result<Challenge, MessageboxError> {
        let (send, recv) = oneshot::channel();
        let msg = AuthMessage::CreateChallenge {
            purpose,
            sender: send,
        };
        let _ = self.sender.send(msg).await;
        recv.await.map_err(|_| MessageboxError::KilledSender)?
    }

    pub async fn handle_response(
        &self,
        response: ChallengeResponse,
        verified: bool,
    ) -> Result<AuthResult, MessageboxError> {
        let (send, recv) = oneshot::channel();
        let msg = AuthMessage::HandleResponse {
            response,
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
