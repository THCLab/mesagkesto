use crate::{messagebox::MessageBox, MessageboxError};
use actix_web::{
    dev::Server, http::StatusCode, web::Data, App, HttpResponse, HttpServer, ResponseError,
};
use anyhow::Result;
use keri_controller::IdentifierPrefix;
use keri_core::actor::prelude::SelfAddressingIdentifier;
use keri_core::{event_message::cesr_adapter::ParseError, oobi::Role};
use std::{net::ToSocketAddrs, sync::Arc};
use tracing_actix_web::TracingLogger;

pub struct MessageBoxListener {
    pub messagebox: MessageBox,
}

impl MessageBoxListener {
    pub fn listen_http(&self, addr: impl ToSocketAddrs) -> Result<Server> {
        let state = Data::new(Arc::new(self.messagebox.clone()));
        Ok(HttpServer::new(move || {
            App::new()
                .wrap(TracingLogger::default())
                .app_data(state.clone())
                .route(
                    "/introduce",
                    actix_web::web::get().to(http_handlers::introduce),
                )
                .route(
                    "/oobi/{id}",
                    actix_web::web::get().to(http_handlers::get_eid_oobi),
                )
                .route(
                    "/oobi/{cid}/{role}/{eid}",
                    actix_web::web::get().to(http_handlers::get_cid_oobi),
                )
                .route(
                    "/register",
                    actix_web::web::post().to(http_handlers::register),
                )
                .route(
                    "/",
                    actix_web::web::post().to(http_handlers::process_message),
                )
                .route(
                    "/resolve",
                    actix_web::web::post().to(http_handlers::resolve_oobi),
                )
                .route(
                    "/messages/{said}",
                    actix_web::web::get().to(http_handlers::get_response),
                )
                .route(
                    "/auth/challenge",
                    actix_web::web::get().to(http_handlers::auth_challenge),
                )
                .route(
                    "/auth/respond",
                    actix_web::web::post().to(http_handlers::auth_respond),
                )
                .route(
                    "/auth/session",
                    actix_web::web::delete().to(http_handlers::auth_revoke),
                )
                .route(
                    "/mailbox",
                    actix_web::web::get().to(http_handlers::get_mailbox),
                )
                .route(
                    "/mailbox",
                    actix_web::web::delete().to(http_handlers::delete_mailbox),
                )
                .route(
                    "/ws",
                    actix_web::web::get().to(http_handlers::ws_upgrade),
                )
                .route(
                    "/mailbox/acl",
                    actix_web::web::put().to(http_handlers::set_acl),
                )
                .route(
                    "/mailbox/acl",
                    actix_web::web::get().to(http_handlers::get_acl),
                )
        })
        .bind(addr)?
        .run())
    }
}

mod http_handlers {
    use std::sync::Arc;

    use crate::{messagebox::MessageBox, MessageboxError};
    use actix_web::{http::header::ContentType, web, HttpResponse};
    use keri_core::actor::prelude::SelfAddressingIdentifier;
    use keri_core::{
        actor::parse_reply_stream,
        event_message::signed_event_message::{Message, Op},
        oobi::Role,
        prefix::IdentifierPrefix,
        query::reply_event::SignedReply,
    };
    use tracing::{debug, warn};

    use crate::auth::AuthResult;
    use crate::ws_session::WsSession;

    use super::ApiError;

    fn oobis_to_cesr_stream(
        oobis: &mut impl Iterator<Item = SignedReply>,
    ) -> Result<Vec<u8>, ApiError> {
        oobis.try_fold(vec![], |mut acc, sr| {
            let mut oobi = Message::Op(Op::Reply(sr)).to_cesr()?;

            acc.append(&mut oobi);
            Ok(acc)
        })
    }

    pub async fn introduce(data: web::Data<Arc<MessageBox>>) -> Result<HttpResponse, ApiError> {
        debug!("GET /introduce");
        let oobi = data.oobi();
        debug!(oobi = ?oobi, "GET /introduce -> 200");
        Ok(HttpResponse::Ok().json(oobi))
    }

    /// Returns stream of signed reply messages that has endpoint identifier
    /// location schemas inside.
    pub async fn get_eid_oobi(
        eid: web::Path<IdentifierPrefix>,
        data: web::Data<Arc<MessageBox>>,
    ) -> Result<HttpResponse, ApiError> {
        debug!(eid = %eid, "GET /oobi/eid");
        let loc_scheme = data.get_loc_scheme_for_id(&eid).await?.unwrap_or_default();
        let oobis: Vec<u8> = oobis_to_cesr_stream(&mut loc_scheme.into_iter())?;
        debug!(eid = %eid, body_len = oobis.len(), "GET /oobi/eid -> 200");
        Ok(HttpResponse::Ok()
            .content_type(ContentType::plaintext())
            .body(oobis))
    }

    pub async fn get_cid_oobi(
        path: web::Path<(IdentifierPrefix, Role, IdentifierPrefix)>,
        data: web::Data<Arc<MessageBox>>,
    ) -> Result<HttpResponse, ApiError> {
        let (cid, role, eid) = path.into_inner();
        debug!(%cid, ?role, %eid, "GET /oobi/cid/role/eid");

        let end_role_feature =
            data.oobi_handle
                .get_role_oobi(cid.clone(), role.clone(), eid.clone());
        let loc_scheme_feature = data.get_loc_scheme_for_id(&eid);
        let (end_role, loc_scheme) = tokio::join!(end_role_feature, loc_scheme_feature);
        let oobis = oobis_to_cesr_stream(
            &mut end_role
                .ok_or(ApiError::MissingEndRoleOobi(cid.clone(), role.clone()))?
                .into_iter()
                .chain(loc_scheme?.unwrap_or_default().into_iter()),
        )?;

        debug!(%cid, ?role, %eid, body_len = oobis.len(), "GET /oobi/cid/role/eid -> 200");
        Ok(HttpResponse::Ok()
            .content_type(ContentType::plaintext())
            .body(oobis))
    }

    pub async fn process_message(
        body: String,
        data: web::Data<Arc<MessageBox>>,
    ) -> Result<HttpResponse, ApiError> {
        debug!(body_len = body.len(), "POST /");
        let result = data.process_message(body).await;
        Ok(match result {
            Ok(Some(response)) => {
                debug!(response_len = response.len(), "POST / -> 200 (with body)");
                HttpResponse::Ok().body(response)
            }
            Ok(None) => {
                debug!("POST / -> 200 (empty)");
                HttpResponse::Ok().finish()
            }
            Err(MessageboxError::VerificationFailure) => {
                warn!("POST / -> 401 verification failure");
                HttpResponse::Unauthorized().finish()
            }
            Err(MessageboxError::ResponseNotReady(ref said)) => {
                debug!(said = %said, "POST / -> 202 response not ready");
                let message = format!(
                    "Missing event, need to ask later on `/messages/{}` endpoint.",
                    said
                );
                HttpResponse::Accepted().body(message)
            }
            Err(MessageboxError::MissingOobi) => {
                warn!("POST / -> 422 missing OOBI");
                HttpResponse::UnprocessableEntity()
                    .body("Missing oobi, need to be provided to `/resolve` endpoint.")
            }
            Err(ref err) => {
                warn!(error = %err, "POST / -> 400");
                let message = format!("Message ignored due to error: {}", err);
                HttpResponse::BadRequest().body(message)
            }
        })
    }

    pub async fn register(
        body: web::Bytes,
        data: web::Data<Arc<MessageBox>>,
    ) -> Result<HttpResponse, ApiError> {
        debug!(body_len = body.len(), body = %String::from_utf8_lossy(&body), "POST /register");
        let replys = parse_reply_stream(&body)?;
        data.oobi_handle.register(replys).await;
        debug!("POST /register -> 200");
        Ok(HttpResponse::Ok()
            .content_type(ContentType::plaintext())
            .body(()))
    }

    pub async fn resolve_oobi(
        body: web::Bytes,
        data: web::Data<Arc<MessageBox>>,
    ) -> Result<HttpResponse, ApiError> {
        let oobi_str = String::from_utf8(body.to_vec()).map_err(|_e| ApiError::Unparsable)?;
        debug!(oobi = %oobi_str, "POST /resolve");
        data.resolve_oobi(oobi_str).await?;
        debug!("POST /resolve -> 200");
        Ok(HttpResponse::Ok().finish())
    }

    pub async fn get_response(
        said: web::Path<SelfAddressingIdentifier>,
        data: web::Data<Arc<MessageBox>>,
    ) -> Result<HttpResponse, ApiError> {
        let sai = said.into_inner();
        debug!(said = %sai, "GET /messages/said");
        data.response_handle
            .get_by_digest(sai.clone())
            .await
            .ok_or(ApiError::UnknownResponse(sai.clone()))?;
        debug!(said = %sai, "GET /messages/said -> 200");
        Ok(HttpResponse::Ok().finish())
    }

    pub async fn auth_challenge(
        query: web::Query<std::collections::HashMap<String, String>>,
        data: web::Data<Arc<MessageBox>>,
    ) -> Result<HttpResponse, ApiError> {
        let auth = data
            .auth_handle
            .as_ref()
            .ok_or(ApiError::AuthNotConfigured)?;

        let purpose_str = query.get("purpose").map(|s| s.as_str()).unwrap_or("identification");
        debug!(purpose = %purpose_str, "GET /auth/challenge");
        let purpose = match purpose_str {
            "registration" => dauthz_core::CeremonyPurpose::Registration,
            _ => dauthz_core::CeremonyPurpose::Identification,
        };

        let challenge = auth.create_challenge(purpose).await?;
        debug!(nonce = %challenge.nonce, purpose = %purpose_str, "GET /auth/challenge -> 200");
        Ok(HttpResponse::Ok().json(challenge))
    }

    /// Payload fields expected inside the CESR-signed JSON envelope.
    #[derive(serde::Deserialize)]
    struct AuthResponsePayload {
        nonce: String,
        entity_aid: String,
        entity_oobi: String,
    }

    pub async fn auth_respond(
        body: String,
        data: web::Data<Arc<MessageBox>>,
    ) -> Result<HttpResponse, ApiError> {
        debug!(body_len = body.len(), "POST /auth/respond");
        let auth = data
            .auth_handle
            .as_ref()
            .ok_or(ApiError::AuthNotConfigured)?;

        // Parse CESR stream: extract JSON payload + cryptographic signatures
        let (payload_bytes, signatures) = MessageBox::split_cesr_stream(body.as_bytes())?;
        let payload_str = String::from_utf8(payload_bytes)
            .map_err(|e| ApiError::MessageboxError(
                crate::MessageboxError::Unparsable(e.to_string()),
            ))?;

        // Deserialize the auth response fields from the signed payload
        let payload: AuthResponsePayload = serde_json::from_str(&payload_str)
            .map_err(|e| ApiError::MessageboxError(
                crate::MessageboxError::Unparsable(e.to_string()),
            ))?;

        debug!(
            entity_aid = %payload.entity_aid,
            entity_oobi = %payload.entity_oobi,
            nonce = %payload.nonce,
            "POST /auth/respond parsed payload, resolving OOBI"
        );

        // Resolve the entity's OOBI so we can verify their signature
        data.resolve_oobi(payload.entity_oobi.clone()).await?;

        // Verify the CESR signature against the sender's KEL
        let verified = data
            .verify_handle
            .verify(&payload_str, signatures.collect())
            .await
            .is_ok();

        debug!(
            entity_aid = %payload.entity_aid,
            verified = verified,
            "POST /auth/respond signature verification complete"
        );

        // Construct the ChallengeResponse for DauthZ from the verified payload
        let response = dauthz_core::ChallengeResponse {
            entity_aid: payload.entity_aid,
            entity_oobi: payload.entity_oobi,
            nonce: payload.nonce,
            signed_challenge: payload_str,
        };

        match auth.handle_response(response, verified).await? {
            AuthResult::Registered { aid, account_id } => {
                debug!(aid = %aid, account_id = %account_id, "POST /auth/respond -> 201 registered");
                let _ = data.mailbox_handle.provision(aid.clone()).await;
                Ok(HttpResponse::Created().json(
                    serde_json::json!({"status": "registered", "aid": aid, "account_id": account_id}),
                ))
            }
            AuthResult::Authenticated { session } => {
                debug!(aid = %session.aid, "POST /auth/respond -> 200 authenticated");
                let _ = data.mailbox_handle.activate(session.aid.clone()).await;
                Ok(HttpResponse::Ok().json(dauthz_core::SessionToken {
                    token: session.token,
                    account_id: session.account_id,
                    aid: session.aid,
                    expires_at: session.expires_at,
                }))
            }
            AuthResult::Invalid(reason) => {
                warn!(reason = %reason, "POST /auth/respond -> 401 invalid");
                Ok(HttpResponse::Unauthorized()
                    .json(serde_json::json!({"error": "invalid", "reason": reason})))
            }
        }
    }

    pub async fn auth_revoke(
        req: actix_web::HttpRequest,
        data: web::Data<Arc<MessageBox>>,
    ) -> Result<HttpResponse, ApiError> {
        debug!("DELETE /auth/session");
        let auth = data
            .auth_handle
            .as_ref()
            .ok_or(ApiError::AuthNotConfigured)?;

        let token = req
            .headers()
            .get("Authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .ok_or(ApiError::Unauthorized)?;

        auth.revoke_session(token).await;
        debug!("DELETE /auth/session -> 200");
        Ok(HttpResponse::Ok().finish())
    }

    pub async fn get_mailbox(
        req: actix_web::HttpRequest,
        data: web::Data<Arc<MessageBox>>,
    ) -> Result<HttpResponse, ApiError> {
        debug!("GET /mailbox");
        let auth = data.auth_handle.as_ref().ok_or(ApiError::AuthNotConfigured)?;
        let token = req
            .headers()
            .get("Authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .ok_or(ApiError::Unauthorized)?;

        let session = auth.validate_session(token).await.ok_or(ApiError::Unauthorized)?;
        debug!(aid = %session.aid, "GET /mailbox authenticated");
        let meta = data.mailbox_handle.get(&session.aid).await;

        match meta {
            Some(m) => {
                debug!(aid = %session.aid, state = ?m.state, "GET /mailbox -> 200");
                Ok(HttpResponse::Ok().json(m))
            }
            None => {
                debug!(aid = %session.aid, "GET /mailbox -> 404");
                Ok(HttpResponse::NotFound().finish())
            }
        }
    }

    pub async fn delete_mailbox(
        req: actix_web::HttpRequest,
        data: web::Data<Arc<MessageBox>>,
    ) -> Result<HttpResponse, ApiError> {
        debug!("DELETE /mailbox");
        let auth = data.auth_handle.as_ref().ok_or(ApiError::AuthNotConfigured)?;
        let token = req
            .headers()
            .get("Authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .ok_or(ApiError::Unauthorized)?;

        let session = auth.validate_session(token).await.ok_or(ApiError::Unauthorized)?;
        debug!(aid = %session.aid, "DELETE /mailbox authenticated");
        data.mailbox_handle.delete(session.aid.clone()).await?;
        debug!(aid = %session.aid, "DELETE /mailbox -> 200");
        Ok(HttpResponse::Ok().finish())
    }

    pub async fn ws_upgrade(
        req: actix_web::HttpRequest,
        stream: web::Payload,
        query: web::Query<std::collections::HashMap<String, String>>,
        data: web::Data<Arc<MessageBox>>,
    ) -> Result<HttpResponse, ApiError> {
        debug!("GET /ws upgrade request");
        let token = query
            .get("token")
            .ok_or(ApiError::Unauthorized)?;

        let auth = data
            .auth_handle
            .as_ref()
            .ok_or(ApiError::AuthNotConfigured)?;

        let session = auth
            .validate_session(token)
            .await
            .ok_or(ApiError::Unauthorized)?;

        debug!(aid = %session.aid, "GET /ws -> 101 upgrading");
        let ws_session = WsSession {
            aid: session.aid,
            last_hb: std::time::Instant::now(),
            manager: data.connection_manager.clone(),
        };

        actix_web_actors::ws::start(ws_session, &req, stream)
            .map_err(|e| ApiError::MessageboxError(
                crate::MessageboxError::Unparsable(e.to_string()),
            ))
    }

    #[derive(serde::Deserialize)]
    pub struct AclPayload {
        tokens: Vec<String>,
    }

    pub async fn set_acl(
        req: actix_web::HttpRequest,
        body: web::Json<AclPayload>,
        data: web::Data<Arc<MessageBox>>,
    ) -> Result<HttpResponse, ApiError> {
        debug!("PUT /mailbox/acl");
        let auth = data.auth_handle.as_ref().ok_or(ApiError::AuthNotConfigured)?;
        let token = req
            .headers()
            .get("Authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .ok_or(ApiError::Unauthorized)?;

        let session = auth.validate_session(token).await.ok_or(ApiError::Unauthorized)?;
        let tokens = body.into_inner().tokens;
        debug!(aid = %session.aid, token_count = tokens.len(), "PUT /mailbox/acl authenticated");
        data.acl_handle
            .set_tokens(session.aid.clone(), tokens)
            .await?;
        debug!(aid = %session.aid, "PUT /mailbox/acl -> 200");
        Ok(HttpResponse::Ok().finish())
    }

    pub async fn get_acl(
        req: actix_web::HttpRequest,
        data: web::Data<Arc<MessageBox>>,
    ) -> Result<HttpResponse, ApiError> {
        debug!("GET /mailbox/acl");
        let auth = data.auth_handle.as_ref().ok_or(ApiError::AuthNotConfigured)?;
        let token = req
            .headers()
            .get("Authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .ok_or(ApiError::Unauthorized)?;

        let session = auth.validate_session(token).await.ok_or(ApiError::Unauthorized)?;
        let tokens = data.acl_handle.get_tokens(&session.aid).await;
        debug!(aid = %session.aid, token_count = tokens.len(), "GET /mailbox/acl -> 200");
        Ok(HttpResponse::Ok().json(serde_json::json!({"tokens": tokens})))
    }
}

#[derive(thiserror::Error, Debug)]
pub enum ApiError {
    #[error(transparent)]
    KeriError(#[from] keri_core::error::Error),
    #[error(transparent)]
    ParseError(#[from] ParseError),
    #[error(transparent)]
    MessageboxError(#[from] MessageboxError),
    #[error("Can't be parsed")]
    Unparsable,
    #[error("No end role oobi of identifier: {0}, {1:?}")]
    MissingEndRoleOobi(IdentifierPrefix, Role),
    #[error("Unknown response said: {0}")]
    UnknownResponse(SelfAddressingIdentifier),
    #[error("Authentication not configured")]
    AuthNotConfigured,
    #[error("Unauthorized")]
    Unauthorized,
}

impl ResponseError for ApiError {
    fn status_code(&self) -> StatusCode {
        match self {
            ApiError::Unauthorized => StatusCode::UNAUTHORIZED,
            ApiError::AuthNotConfigured => StatusCode::NOT_FOUND,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    fn error_response(&self) -> HttpResponse {
        HttpResponse::build(self.status_code()).body(self.to_string())
    }
}
