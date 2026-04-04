use crate::{messagebox::MessageBox, MessageboxError};
use actix_web::{
    dev::Server, http::StatusCode, web::Data, App, HttpResponse, HttpServer, ResponseError,
};
use anyhow::Result;
use keri_sdk::{IdentifierPrefix, SelfAddressingIdentifier};
use keri_sdk::keri_core::{event_message::cesr_adapter::ParseError, oobi::Role};
use std::{net::ToSocketAddrs, sync::Arc};
use tracing_actix_web::TracingLogger;

pub struct MessageBoxListener {
    pub messagebox: MessageBox,
    pub mqtt_url: Option<String>,
}

impl MessageBoxListener {
    pub fn listen_http(&self, addr: impl ToSocketAddrs) -> Result<Server> {
        let state = Data::new(Arc::new(self.messagebox.clone()));
        let mqtt_url = Data::new(self.mqtt_url.clone());
        Ok(HttpServer::new(move || {
            App::new()
                .wrap(TracingLogger::default())
                .app_data(state.clone())
                .app_data(mqtt_url.clone())
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
                .route("/ws", actix_web::web::get().to(http_handlers::ws_upgrade))
                .route(
                    "/mailbox/acl",
                    actix_web::web::put().to(http_handlers::set_acl),
                )
                .route(
                    "/mailbox/acl",
                    actix_web::web::get().to(http_handlers::get_acl),
                )
                .route(
                    "/mqtt/authz",
                    actix_web::web::post().to(http_handlers::mqtt_authz),
                )
                // Channel endpoints (authenticated)
                .route(
                    "/channels",
                    actix_web::web::get().to(http_handlers::list_channels),
                )
                .route(
                    "/channels/pending",
                    actix_web::web::get().to(http_handlers::pending_invites),
                )
                .route(
                    "/channels/{said}",
                    actix_web::web::get().to(http_handlers::get_channel),
                )
                .route(
                    "/channels/{said}/messages",
                    actix_web::web::get().to(http_handlers::get_channel_messages),
                )
                // Broadcast endpoints (public, no auth)
                .route(
                    "/broadcasts",
                    actix_web::web::get().to(http_handlers::list_broadcasts),
                )
                .route(
                    "/broadcast/{aid}/{topic}",
                    actix_web::web::get().to(http_handlers::discover_broadcast),
                )
                .route(
                    "/broadcast/{aid}/{topic}/messages",
                    actix_web::web::get().to(http_handlers::get_broadcast_messages),
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
    use keri_sdk::{IdentifierPrefix, Oobi, SelfAddressingIdentifier};
    use keri_sdk::keri_core::{
        actor::parse_reply_stream,
        event_message::signed_event_message::{Message, Op},
        oobi::Role,
        query::reply_event::SignedReply,
    };
    use tracing::{debug, warn};

    use crate::auth::AuthResult;
    use crate::ws_session::WsSession;

    use super::ApiError;

    /// JWT claims for MQTT authentication with EMQX.
    #[derive(serde::Serialize, serde::Deserialize)]
    struct MqttClaims {
        /// AID — used as MQTT client_id
        sub: String,
        /// Expiry (Unix timestamp)
        exp: usize,
        /// Issued at (Unix timestamp)
        iat: usize,
    }

    /// Build a signed JWT for the given AID using the shared secret.
    fn build_mqtt_jwt(aid: &str, jwt_secret: &str, expires_at: &str) -> Result<String, ApiError> {
        let now = chrono::Utc::now().timestamp() as usize;
        let exp = expires_at
            .parse::<chrono::DateTime<chrono::Utc>>()
            .map(|dt| dt.timestamp() as usize)
            .unwrap_or(now + 3600);

        let claims = MqttClaims {
            sub: aid.to_string(),
            exp,
            iat: now,
        };
        let key = jsonwebtoken::EncodingKey::from_secret(jwt_secret.as_bytes());
        let header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256);
        jsonwebtoken::encode(&header, &claims, &key).map_err(|e| {
            ApiError::MessageboxError(crate::MessageboxError::AuthError(format!(
                "JWT signing failed: {}",
                e
            )))
        })
    }

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
            Err(MessageboxError::AclDenied(ref sender)) => {
                warn!(sender = %sender, "POST / -> 403 ACL denied");
                HttpResponse::Forbidden()
                    .json(serde_json::json!({"error": "acl_denied", "reason": format!("Sender {} is not authorized to send to this mailbox", sender)}))
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
        data.resolve_oobi_multi(&oobi_str).await?;
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

    #[derive(serde::Deserialize)]
    pub struct ChallengeQuery {
        purpose: Option<String>,
        oobi: String,
    }

    /// Extract the AID from an OOBI JSON string (single object or array).
    /// Prefers `cid` from EndRole entries (the transferable AID) over `eid`
    /// from LocationScheme entries (which may be a witness basic prefix).
    fn aid_from_oobi(oobi_str: &str) -> Result<String, ApiError> {
        // Try parsing as array first (real-world OOBIs are often arrays of
        // LocationScheme + EndRole entries)
        if let Ok(oobis) = serde_json::from_str::<Vec<Oobi>>(oobi_str) {
            // Prefer cid from EndRole entries — that's the controlling identifier
            for oobi in &oobis {
                if let Oobi::EndRole(er) = oobi {
                    return Ok(er.cid.to_string());
                }
            }
            // Fall back to eid from LocationScheme
            for oobi in &oobis {
                if let Oobi::Location(loc) = oobi {
                    return Ok(loc.eid.to_string());
                }
            }
            Err(ApiError::MessageboxError(
                crate::MessageboxError::OobiParsingError,
            ))
        } else {
            // Single OOBI object
            let oobi: Oobi = serde_json::from_str(oobi_str)
                .map_err(|_| ApiError::MessageboxError(crate::MessageboxError::OobiParsingError))?;
            let aid = match oobi {
                Oobi::Location(loc) => loc.eid.to_string(),
                Oobi::EndRole(er) => er.cid.to_string(),
            };
            Ok(aid)
        }
    }

    pub async fn auth_challenge(
        query: web::Query<ChallengeQuery>,
        data: web::Data<Arc<MessageBox>>,
    ) -> Result<HttpResponse, ApiError> {
        let auth = data
            .auth_handle
            .as_ref()
            .ok_or(ApiError::AuthNotConfigured)?;

        let entity_aid = aid_from_oobi(&query.oobi)?;

        let purpose_str = query.purpose.as_deref().unwrap_or("identification");
        debug!(
            purpose = %purpose_str,
            entity_aid = %entity_aid,
            entity_oobi = %query.oobi,
            "GET /auth/challenge"
        );
        let purpose = match purpose_str {
            "registration" => dauthz_core::CeremonyPurpose::Registration,
            _ => dauthz_core::CeremonyPurpose::Identification,
        };

        // Resolve the entity's OOBI(s) early so KEL is cached for later verification.
        // Handles both single OOBI objects and arrays (LocationScheme + EndRole entries).
        data.resolve_oobi_multi(&query.oobi).await?;

        let cesr_stream = auth
            .create_challenge(purpose, entity_aid.clone(), query.oobi.clone())
            .await?;
        debug!(
            entity_aid = %entity_aid,
            body_len = cesr_stream.len(),
            "GET /auth/challenge -> 200"
        );
        Ok(HttpResponse::Ok()
            .content_type(ContentType::plaintext())
            .body(cesr_stream))
    }

    /// Payload inside the CESR-signed envelope for auth response.
    /// Only the nonce is needed — the server already knows the bound AID.
    #[derive(serde::Deserialize)]
    struct AuthResponsePayload {
        nonce: String,
    }

    pub async fn auth_respond(
        body: String,
        data: web::Data<Arc<MessageBox>>,
        mqtt_url: web::Data<Option<String>>,
    ) -> Result<HttpResponse, ApiError> {
        debug!(body_len = body.len(), "POST /auth/respond");
        let auth = data
            .auth_handle
            .as_ref()
            .ok_or(ApiError::AuthNotConfigured)?;

        // Parse CESR stream: extract JSON payload + cryptographic signatures
        let (payload_bytes, signatures) = MessageBox::split_cesr_stream(body.as_bytes())?;
        let payload_str = String::from_utf8(payload_bytes).map_err(|e| {
            ApiError::MessageboxError(crate::MessageboxError::Unparsable(e.to_string()))
        })?;

        let payload: AuthResponsePayload = serde_json::from_str(&payload_str).map_err(|e| {
            ApiError::MessageboxError(crate::MessageboxError::Unparsable(e.to_string()))
        })?;

        debug!(nonce = %payload.nonce, "POST /auth/respond parsed nonce");

        // Verify the CESR signature against the sender's KEL
        // (OOBI was already resolved during challenge creation)
        let verified = data
            .verify_handle
            .verify(&payload_str, signatures.collect())
            .await
            .is_ok();

        debug!(nonce = %payload.nonce, verified = verified, "POST /auth/respond verification complete");

        match auth.handle_response(payload.nonce, verified).await? {
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

                // Build MQTT JWT if jwt_secret is configured
                let mqtt_token = data
                    .jwt_secret
                    .as_ref()
                    .and_then(|secret| {
                        build_mqtt_jwt(&session.aid, secret, &session.expires_at).ok()
                    });

                let mut response = serde_json::json!({
                    "token": session.token,
                    "account_id": session.account_id,
                    "aid": session.aid,
                    "expires_at": session.expires_at,
                });
                if let Some(jwt) = mqtt_token {
                    response["mqtt_token"] = serde_json::Value::String(jwt);
                }
                if let Some(url) = mqtt_url.as_ref() {
                    response["mqtt_url"] = serde_json::Value::String(url.clone());
                }
                Ok(HttpResponse::Ok().json(response))
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

        let session = auth
            .validate_session(token)
            .await
            .ok_or(ApiError::Unauthorized)?;
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

        let session = auth
            .validate_session(token)
            .await
            .ok_or(ApiError::Unauthorized)?;
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
        let token = query.get("token").ok_or(ApiError::Unauthorized)?;

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

        actix_web_actors::ws::start(ws_session, &req, stream).map_err(|e| {
            ApiError::MessageboxError(crate::MessageboxError::Unparsable(e.to_string()))
        })
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

        let session = auth
            .validate_session(token)
            .await
            .ok_or(ApiError::Unauthorized)?;
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

        let session = auth
            .validate_session(token)
            .await
            .ok_or(ApiError::Unauthorized)?;
        let tokens = data.acl_handle.get_tokens(&session.aid).await;
        debug!(aid = %session.aid, token_count = tokens.len(), "GET /mailbox/acl -> 200");
        Ok(HttpResponse::Ok().json(serde_json::json!({"tokens": tokens})))
    }

    // --- Channel endpoints ---

    #[derive(serde::Deserialize)]
    pub struct ChannelMessagesQuery {
        s: Option<usize>,
    }

    /// List all channels the authenticated user is a member of.
    pub async fn list_channels(
        req: actix_web::HttpRequest,
        data: web::Data<Arc<MessageBox>>,
    ) -> Result<HttpResponse, ApiError> {
        debug!("GET /channels");
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

        let session = auth
            .validate_session(token)
            .await
            .ok_or(ApiError::Unauthorized)?;
        let channels = data.channel_handle.list_for_aid(&session.aid).await;
        debug!(aid = %session.aid, count = channels.len(), "GET /channels -> 200");
        Ok(HttpResponse::Ok().json(channels))
    }

    /// List pending channel invites for the authenticated user.
    pub async fn pending_invites(
        req: actix_web::HttpRequest,
        data: web::Data<Arc<MessageBox>>,
    ) -> Result<HttpResponse, ApiError> {
        debug!("GET /channels/pending");
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

        let session = auth
            .validate_session(token)
            .await
            .ok_or(ApiError::Unauthorized)?;
        let raw_invites = data
            .channel_handle
            .get_pending_invites(&session.aid)
            .await;

        // Enrich invite tuples with channel metadata
        let mut result = Vec::new();
        for (channel_said, invite_json) in &raw_invites {
            let invite_data: serde_json::Value =
                serde_json::from_str(invite_json).unwrap_or_default();
            let inviter = invite_data
                .get("inviter")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();

            // Look up channel for type and topic
            let (channel_type, topic) =
                if let Some(ch) = data.channel_handle.get(channel_said).await {
                    (
                        serde_json::to_value(&ch.channel_type)
                            .ok()
                            .and_then(|v| v.as_str().map(|s| s.to_string()))
                            .unwrap_or_else(|| "group".to_string()),
                        ch.topic.clone(),
                    )
                } else {
                    ("group".to_string(), None)
                };

            result.push(serde_json::json!({
                "channel_said": channel_said,
                "channel_type": channel_type,
                "topic": topic,
                "inviter_aid": inviter,
            }));
        }

        debug!(aid = %session.aid, count = result.len(), "GET /channels/pending -> 200");
        Ok(HttpResponse::Ok().json(result))
    }

    /// Get channel metadata by SAID (authenticated, must be member).
    pub async fn get_channel(
        said: web::Path<String>,
        req: actix_web::HttpRequest,
        data: web::Data<Arc<MessageBox>>,
    ) -> Result<HttpResponse, ApiError> {
        let said = said.into_inner();
        debug!(said = %said, "GET /channels/said");
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

        let session = auth
            .validate_session(token)
            .await
            .ok_or(ApiError::Unauthorized)?;

        let channel = data
            .channel_handle
            .get(&said)
            .await
            .ok_or(ApiError::MessageboxError(
                crate::MessageboxError::UnknownMessage("Channel not found".into()),
            ))?;

        // Check read permission
        if !channel.can_read(&session.aid) {
            return Err(ApiError::Unauthorized);
        }

        Ok(HttpResponse::Ok().json(channel))
    }

    /// Get channel messages by sequence number (authenticated, must be member).
    pub async fn get_channel_messages(
        said: web::Path<String>,
        query: web::Query<ChannelMessagesQuery>,
        req: actix_web::HttpRequest,
        data: web::Data<Arc<MessageBox>>,
    ) -> Result<HttpResponse, ApiError> {
        let said = said.into_inner();
        let from_sn = query.s.unwrap_or(0);
        debug!(said = %said, from_sn = from_sn, "GET /channels/said/messages");

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

        let session = auth
            .validate_session(token)
            .await
            .ok_or(ApiError::Unauthorized)?;

        let channel = data
            .channel_handle
            .get(&said)
            .await
            .ok_or(ApiError::MessageboxError(
                crate::MessageboxError::UnknownMessage("Channel not found".into()),
            ))?;

        if !channel.can_read(&session.aid) {
            return Err(ApiError::Unauthorized);
        }

        match data
            .storage_handle
            .get_channel_by_index(&said, from_sn)
            .await
        {
            Some(messages) => Ok(HttpResponse::Ok()
                .content_type(actix_web::http::header::ContentType::json())
                .body(messages)),
            None => Ok(HttpResponse::Ok().json(serde_json::json!({"last_sn": null, "messages": []}))),
        }
    }

    /// List all public broadcast channels on this instance (no auth).
    pub async fn list_broadcasts(
        data: web::Data<Arc<MessageBox>>,
    ) -> Result<HttpResponse, ApiError> {
        debug!("GET /broadcasts");
        let all = data.channel_handle.list_all().await;
        let broadcasts: Vec<_> = all
            .into_iter()
            .filter(|ch| {
                ch.channel_type == crate::channel::ChannelType::Broadcast
            })
            .collect();
        debug!(count = broadcasts.len(), "GET /broadcasts -> 200");
        Ok(HttpResponse::Ok().json(broadcasts))
    }

    /// Discover a broadcast channel by owner AID and topic name (no auth).
    pub async fn discover_broadcast(
        path: web::Path<(String, String)>,
        data: web::Data<Arc<MessageBox>>,
    ) -> Result<HttpResponse, ApiError> {
        let (aid, topic) = path.into_inner();
        debug!(aid = %aid, topic = %topic, "GET /broadcast/aid/topic");

        let channel = data
            .channel_handle
            .get_by_topic(&aid, &topic)
            .await
            .ok_or(ApiError::MessageboxError(
                crate::MessageboxError::UnknownMessage("Broadcast not found".into()),
            ))?;

        // Only expose public broadcasts
        if channel.channel_type != crate::channel::ChannelType::Broadcast {
            return Err(ApiError::Unauthorized);
        }

        Ok(HttpResponse::Ok().json(channel))
    }

    /// Get public broadcast messages (no auth required).
    pub async fn get_broadcast_messages(
        path: web::Path<(String, String)>,
        query: web::Query<ChannelMessagesQuery>,
        data: web::Data<Arc<MessageBox>>,
    ) -> Result<HttpResponse, ApiError> {
        let (aid, topic) = path.into_inner();
        let from_sn = query.s.unwrap_or(0);
        debug!(aid = %aid, topic = %topic, from_sn = from_sn, "GET /broadcast/aid/topic/messages");

        let channel = data
            .channel_handle
            .get_by_topic(&aid, &topic)
            .await
            .ok_or(ApiError::MessageboxError(
                crate::MessageboxError::UnknownMessage("Broadcast not found".into()),
            ))?;

        if channel.channel_type != crate::channel::ChannelType::Broadcast {
            return Err(ApiError::Unauthorized);
        }

        match data
            .storage_handle
            .get_channel_by_index(&channel.said, from_sn)
            .await
        {
            Some(messages) => Ok(HttpResponse::Ok()
                .content_type(actix_web::http::header::ContentType::json())
                .body(messages)),
            None => Ok(HttpResponse::Ok().json(serde_json::json!({"last_sn": null, "messages": []}))),
        }
    }

    /// EMQX HTTP authorization hook.
    /// Called by EMQX on each PUBLISH to check sender-level ACL.
    /// Only enforces ACL for publishes to `msg/inbox/{recipient_aid}`.
    #[derive(serde::Deserialize)]
    pub struct MqttAuthzRequest {
        clientid: String,
        topic: String,
        action: String,
    }

    pub async fn mqtt_authz(
        body: web::Json<MqttAuthzRequest>,
        data: web::Data<Arc<MessageBox>>,
    ) -> Result<HttpResponse, ApiError> {
        let req = body.into_inner();
        debug!(
            clientid = %req.clientid,
            topic = %req.topic,
            action = %req.action,
            "POST /mqtt/authz"
        );

        let allow = || HttpResponse::Ok().json(serde_json::json!({"result": "allow"}));
        let deny = || HttpResponse::Ok().json(serde_json::json!({"result": "deny"}));

        // Legacy inbox topic (kept for backward compat)
        if req.topic.starts_with("msg/inbox/") {
            if req.action == "publish" {
                if let Some(recipient_aid) = req.topic.strip_prefix("msg/inbox/") {
                    let acl_tokens = data.acl_handle.get_tokens(recipient_aid).await;
                    if !acl_tokens.is_empty() && !acl_tokens.contains(&req.clientid) {
                        debug!(sender = %req.clientid, recipient = %recipient_aid, "MQTT authz denied: ACL");
                        return Ok(deny());
                    }
                }
            }
            return Ok(allow());
        }

        // Channel topics: ch/{said}/msg or ch/{said}/meta
        if let Some(rest) = req.topic.strip_prefix("ch/") {
            if let Some((channel_said, sub_topic)) = rest.split_once('/') {
                if let Some(channel) = data.channel_handle.get(channel_said).await {
                    match (req.action.as_str(), sub_topic) {
                        ("publish", "msg") => {
                            // Check write permission
                            if channel.can_write(&req.clientid) {
                                return Ok(allow());
                            }
                            debug!(sender = %req.clientid, channel = %channel_said, "MQTT authz denied: no write permission");
                            return Ok(deny());
                        }
                        ("subscribe", "msg") | ("subscribe", "meta") => {
                            // Public broadcasts allow anonymous subscribe
                            if channel.can_read(&req.clientid) {
                                return Ok(allow());
                            }
                            debug!(sender = %req.clientid, channel = %channel_said, "MQTT authz denied: no read permission");
                            return Ok(deny());
                        }
                        _ => {}
                    }
                } else {
                    debug!(channel = %channel_said, "MQTT authz denied: channel not found");
                    return Ok(deny());
                }
            }
        }

        // Personal notification topic: sys/inbox/{aid}
        if let Some(aid) = req.topic.strip_prefix("sys/inbox/") {
            if req.action == "subscribe" && req.clientid == aid {
                return Ok(allow());
            }
            // Deny publish to sys/inbox (server-internal only) and subscribe to others' inboxes
            return Ok(deny());
        }

        // Default deny for unknown topics
        Ok(deny())
    }
}

#[derive(thiserror::Error, Debug)]
pub enum ApiError {
    #[error(transparent)]
    KeriError(#[from] keri_sdk::keri_core::error::Error),
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
