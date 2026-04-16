use crate::{messagebox::MessageBox, MessageboxError};
use actix_web::{
    dev::Server, http::StatusCode, web::Data, App, HttpResponse, HttpServer, ResponseError,
};
use anyhow::Result;
use keri_sdk::keri_core::{event_message::cesr_adapter::ParseError, oobi::Role};
use keri_sdk::{IdentifierPrefix, SelfAddressingIdentifier};
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
            // 10 MB payload limit (for vault image uploads)
            let payload_cfg = actix_web::web::PayloadConfig::new(10 * 1024 * 1024);
            App::new()
                .wrap(TracingLogger::default())
                .app_data(state.clone())
                .app_data(mqtt_url.clone())
                .app_data(payload_cfg)
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
                    "/broadcast/{said}",
                    actix_web::web::get().to(http_handlers::get_broadcast),
                )
                .route(
                    "/broadcast/{said}/messages",
                    actix_web::web::get().to(http_handlers::get_broadcast_messages),
                )
                // Formal Mail federation endpoints
                .route(
                    "/mail/deliver",
                    actix_web::web::post().to(http_handlers::mail_deliver),
                )
                .route(
                    "/mail/receipt",
                    actix_web::web::post().to(http_handlers::mail_receipt),
                )
                .route(
                    "/mail/messages",
                    actix_web::web::get().to(http_handlers::mail_get_messages),
                )
                .route(
                    "/mail/messages/{seq}",
                    actix_web::web::delete().to(http_handlers::mail_delete_message),
                )
                // Storage Vault endpoints
                .route(
                    "/vault/{said}",
                    actix_web::web::put().to(http_handlers::vault_put),
                )
                .route(
                    "/vault/{said}",
                    actix_web::web::get().to(http_handlers::vault_get),
                )
                // Admin endpoints (protected by admin AID session)
                .route(
                    "/admin/invites",
                    actix_web::web::post().to(http_handlers::admin_create_invite),
                )
                .route(
                    "/admin/invites",
                    actix_web::web::get().to(http_handlers::admin_list_invites),
                )
                .route(
                    "/admin/invites/{token}",
                    actix_web::web::delete().to(http_handlers::admin_revoke_invite),
                )
                .route(
                    "/admin/whitelist",
                    actix_web::web::post().to(http_handlers::admin_add_whitelist),
                )
                .route(
                    "/admin/whitelist",
                    actix_web::web::get().to(http_handlers::admin_list_whitelist),
                )
                .route(
                    "/admin/whitelist/{aid}",
                    actix_web::web::delete().to(http_handlers::admin_remove_whitelist),
                )
        })
        .bind(addr)?
        .run())
    }
}

pub(crate) mod http_handlers {
    use std::sync::Arc;

    use crate::{messagebox::MessageBox, MessageboxError};
    use actix_web::{http::header::ContentType, web, HttpResponse};
    use keri_sdk::keri_core::{
        actor::parse_reply_stream,
        event_message::signed_event_message::{Message, Op},
        oobi::Role,
        query::reply_event::SignedReply,
    };
    use keri_sdk::{IdentifierPrefix, Oobi, SelfAddressingIdentifier};
    use tracing::{debug, warn};

    use crate::auth::AuthResult;
    use crate::ws_session::WsSession;

    use super::ApiError;

    // --- Response schemas for OpenAPI documentation ---

    #[derive(serde::Serialize, utoipa::ToSchema)]
    pub(crate) struct RegistrationResponse {
        pub status: String,
        pub aid: String,
        pub account_id: String,
    }

    #[derive(serde::Serialize, utoipa::ToSchema)]
    pub(crate) struct AuthenticatedResponse {
        pub token: String,
        pub account_id: String,
        pub aid: String,
        pub expires_at: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub mqtt_token: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub mqtt_url: Option<String>,
    }

    #[derive(serde::Serialize, utoipa::ToSchema)]
    pub(crate) struct AuthErrorResponse {
        pub error: String,
        pub reason: String,
    }

    #[derive(serde::Serialize, utoipa::ToSchema)]
    pub(crate) struct AclTokensResponse {
        pub tokens: Vec<String>,
    }

    #[derive(serde::Serialize, utoipa::ToSchema)]
    pub(crate) struct MqttAuthzResult {
        pub result: String,
    }

    #[derive(serde::Serialize, utoipa::ToSchema)]
    pub(crate) struct ChannelMessagesResponse {
        pub last_sn: Option<u64>,
        pub messages: Vec<serde_json::Value>,
    }

    #[derive(serde::Serialize, utoipa::ToSchema)]
    pub(crate) struct PendingInviteItem {
        pub channel_said: String,
        pub channel_type: String,
        pub topic: Option<String>,
        pub inviter_aid: String,
    }

    #[derive(serde::Serialize, utoipa::ToSchema)]
    pub(crate) struct MailDeliveryReceipt {
        pub message_id: String,
        pub receipt_type: String,
        pub signer_aid: String,
        pub timestamp: String,
        pub cesr_signature: String,
    }

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

    /// Get this messagebox's own OOBI.
    ///
    /// Returns the messagebox's LocationScheme OOBI for discovery.
    #[utoipa::path(
        get,
        path = "/introduce",
        tag = "KERI",
        responses(
            (status = 200, description = "Messagebox location scheme", body = serde_json::Value)
        )
    )]
    pub async fn introduce(data: web::Data<Arc<MessageBox>>) -> Result<HttpResponse, ApiError> {
        debug!("GET /introduce");
        let oobi = data.oobi();
        debug!(oobi = ?oobi, "GET /introduce -> 200");
        Ok(HttpResponse::Ok().json(oobi))
    }

    /// Get location scheme for an endpoint identifier.
    ///
    /// Returns a CESR stream of signed reply messages containing the
    /// location scheme(s) for the given endpoint identifier.
    #[utoipa::path(
        get,
        path = "/oobi/{id}",
        tag = "KERI",
        params(
            ("id" = String, Path, description = "Endpoint identifier prefix")
        ),
        responses(
            (status = 200, description = "CESR stream of signed location scheme replies",
             content_type = "text/plain", body = String)
        )
    )]
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

    /// Get end-role OOBI with location scheme.
    ///
    /// Returns a CESR stream containing the end-role authorization reply
    /// and location scheme(s) for the given controller/role/endpoint triple.
    #[utoipa::path(
        get,
        path = "/oobi/{cid}/{role}/{eid}",
        tag = "KERI",
        params(
            ("cid" = String, Path, description = "Controlling identifier prefix"),
            ("role" = String, Path, description = "KERI role (witness, watcher, messagebox, controller)"),
            ("eid" = String, Path, description = "Endpoint identifier prefix")
        ),
        responses(
            (status = 200, description = "CESR stream of end-role + location scheme replies",
             content_type = "text/plain", body = String),
            (status = 500, description = "Missing end-role OOBI")
        )
    )]
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
                .chain(loc_scheme?.unwrap_or_default()),
        )?;

        debug!(%cid, ?role, %eid, body_len = oobis.len(), "GET /oobi/cid/role/eid -> 200");
        Ok(HttpResponse::Ok()
            .content_type(ContentType::plaintext())
            .body(oobis))
    }

    /// Process a CESR-signed message.
    ///
    /// Accepts a CESR-encoded message (JSON payload + cryptographic signature attachments).
    /// The sender's OOBI must have been resolved beforehand.
    ///
    /// The body is a raw CESR stream (not JSON). The payload inside is a tagged JSON object:
    /// - `"t": "exn"` for exchange messages (forward, set firebase token)
    /// - `"t": "qry"` for query messages (by sequence number, by digest)
    #[utoipa::path(
        post,
        path = "/",
        tag = "KERI",
        request_body(content = String, content_type = "text/plain",
                     description = "CESR-encoded message stream (JSON payload + signature attachments)"),
        responses(
            (status = 200, description = "Message processed successfully",
             content_type = "text/plain", body = String),
            (status = 202, description = "Response not ready — query later via GET /messages/{said}",
             content_type = "text/plain", body = String),
            (status = 400, description = "Message ignored due to error",
             content_type = "text/plain", body = String),
            (status = 401, description = "Signature verification failed"),
            (status = 403, description = "ACL denied"),
            (status = 422, description = "Missing OOBI — resolve sender's OOBI first via POST /resolve")
        )
    )]
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

    /// Register OOBI reply events.
    ///
    /// Submit a stream of CESR-encoded signed reply messages (location scheme OOBIs)
    /// to register endpoint identifiers.
    #[utoipa::path(
        post,
        path = "/register",
        tag = "KERI",
        request_body(content = String, content_type = "application/octet-stream",
                     description = "CESR stream of signed reply messages"),
        responses(
            (status = 200, description = "OOBIs registered successfully")
        )
    )]
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

    /// Resolve an OOBI.
    ///
    /// Submit an OOBI URL string. The server will resolve it to fetch the
    /// identifier's Key Event Log (KEL), which is required before verifying
    /// messages from that identifier.
    #[utoipa::path(
        post,
        path = "/resolve",
        tag = "KERI",
        request_body(content = String, content_type = "text/plain",
                     description = "OOBI URL to resolve"),
        responses(
            (status = 200, description = "OOBI resolved successfully")
        )
    )]
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

    /// Retrieve async response by SAID.
    ///
    /// When `POST /` returns 202, the response is not yet ready. Poll this
    /// endpoint with the SAID from the 202 response to retrieve it later.
    #[utoipa::path(
        get,
        path = "/messages/{said}",
        tag = "KERI",
        params(
            ("said" = String, Path, description = "Self-Addressing Identifier of the pending response")
        ),
        responses(
            (status = 200, description = "Response is available"),
            (status = 500, description = "Unknown response SAID")
        )
    )]
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

    #[derive(serde::Deserialize, utoipa::IntoParams)]
    pub struct ChallengeQuery {
        /// `registration` for first-time signup, `identification` for login.
        purpose: Option<String>,
        /// Your OOBI as a JSON string. The AID is extracted automatically.
        oobi: String,
        /// Optional invite token for invite-only servers.
        invite_token: Option<String>,
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

    /// Request signed DauthZ challenge bound to an OOBI.
    ///
    /// The server will parse the OOBI to extract the entity's AID, resolve it
    /// to cache the KEL, create a challenge bound to that AID, sign it with
    /// the service's KERI key, and return the signed challenge as a CESR stream.
    ///
    /// Use `purpose=registration` for first-time signup (provisions a mailbox)
    /// or `purpose=identification` for login (issues a session token).
    ///
    /// **Requires `dauthz_state_dir` to be configured on the server.**
    #[utoipa::path(
        get,
        path = "/auth/challenge",
        tag = "Authentication",
        params(ChallengeQuery),
        responses(
            (status = 200, description = "CESR stream: JSON challenge payload + nontransferable receipt couples",
             content_type = "text/plain", body = String),
            (status = 404, description = "Authentication not configured on this server")
        )
    )]
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

        // For registration requests, check registration access policy
        if purpose_str == "registration" {
            data.registration_handle
                .check_access(entity_aid.clone(), query.invite_token.clone())
                .await
                .map_err(|e| ApiError::RegistrationDenied(e.to_string()))?;
        }

        // Resolve the entity's OOBI(s) early so KEL is cached for later verification.
        // Handles both single OOBI objects and arrays (LocationScheme + EndRole entries).
        data.resolve_oobi_multi(&query.oobi).await?;

        let cesr_stream = auth
            .create_challenge(
                purpose,
                entity_aid.clone(),
                query.oobi.clone(),
                query.invite_token.clone(),
            )
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
    #[derive(serde::Deserialize, utoipa::ToSchema)]
    pub(crate) struct AuthResponsePayload {
        nonce: String,
    }

    /// Submit signed challenge response.
    ///
    /// Submit a CESR-signed response to complete DauthZ authentication.
    /// The body is a raw CESR stream — a JSON payload signed with your KERI keys.
    /// The JSON payload inside only needs the nonce from the challenge.
    /// On **registration**: provisions a mailbox, returns account info.
    /// On **identification**: issues a session token (1hr expiry).
    #[utoipa::path(
        post,
        path = "/auth/respond",
        tag = "Authentication",
        request_body(content = String, content_type = "text/plain",
                     description = "CESR-encoded payload with attached signatures containing the challenge nonce"),
        responses(
            (status = 201, description = "Registration successful — mailbox provisioned",
             body = RegistrationResponse),
            (status = 200, description = "Identification successful — session token issued",
             body = AuthenticatedResponse),
            (status = 401, description = "Invalid challenge response",
             body = AuthErrorResponse),
            (status = 404, description = "Authentication not configured on this server")
        )
    )]
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
            AuthResult::Registered {
                aid,
                account_id,
                invite_token,
            } => {
                debug!(aid = %aid, account_id = %account_id, "POST /auth/respond -> 201 registered");
                // Consume the invite token if one was used
                if let Some(token) = invite_token {
                    let _ = data.registration_handle.consume_invite(token).await;
                }
                let _ = data.mailbox_handle.provision(aid.clone()).await;
                Ok(HttpResponse::Created().json(
                    serde_json::json!({"status": "registered", "aid": aid, "account_id": account_id}),
                ))
            }
            AuthResult::Authenticated { session } => {
                debug!(aid = %session.aid, "POST /auth/respond -> 200 authenticated");
                let _ = data.mailbox_handle.activate(session.aid.clone()).await;

                // Build MQTT JWT if jwt_secret is configured
                let mqtt_token = data.jwt_secret.as_ref().and_then(|secret| {
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

    /// Revoke session.
    ///
    /// Revoke the current session token, logging out the client.
    #[utoipa::path(
        delete,
        path = "/auth/session",
        tag = "Authentication",
        security(("bearerAuth" = [])),
        responses(
            (status = 200, description = "Session revoked"),
            (status = 401, description = "Missing or invalid Authorization header"),
            (status = 404, description = "Authentication not configured on this server")
        )
    )]
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

    /// Get mailbox metadata.
    ///
    /// Returns the mailbox metadata for the authenticated AID.
    #[utoipa::path(
        get,
        path = "/mailbox",
        tag = "Mailbox",
        security(("bearerAuth" = [])),
        responses(
            (status = 200, description = "Mailbox metadata", body = crate::mailbox::MailboxMetadata),
            (status = 401, description = "Missing or invalid session token"),
            (status = 404, description = "Mailbox not found (or auth not configured)")
        )
    )]
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

    /// Delete mailbox.
    ///
    /// Permanently delete the mailbox for the authenticated AID.
    /// This removes all messages, ACL tokens, and associated data.
    #[utoipa::path(
        delete,
        path = "/mailbox",
        tag = "Mailbox",
        security(("bearerAuth" = [])),
        responses(
            (status = 200, description = "Mailbox deleted"),
            (status = 401, description = "Missing or invalid session token")
        )
    )]
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

    /// Upgrade to WebSocket connection.
    ///
    /// Upgrade the HTTP connection to a WebSocket for real-time messaging.
    /// Server sends ping every 30 seconds; client must respond with pong.
    /// Connection is closed after 60 seconds without a pong.
    #[utoipa::path(
        get,
        path = "/ws",
        tag = "WebSocket",
        params(
            ("token" = String, Query, description = "Session token obtained from POST /auth/respond")
        ),
        responses(
            (status = 101, description = "WebSocket upgrade successful"),
            (status = 401, description = "Missing or invalid session token")
        )
    )]
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

    #[derive(serde::Deserialize, utoipa::ToSchema)]
    pub struct AclPayload {
        /// Complete set of whitelist tokens (replaces existing set).
        tokens: Vec<String>,
    }

    /// Set ACL whitelist tokens.
    ///
    /// Replace the entire ACL token set for the authenticated AID's mailbox.
    /// Tokens are opaque hex-encoded HMAC-SHA256 values computed client-side.
    #[utoipa::path(
        put,
        path = "/mailbox/acl",
        tag = "Mailbox",
        security(("bearerAuth" = [])),
        request_body = AclPayload,
        responses(
            (status = 200, description = "ACL tokens updated"),
            (status = 401, description = "Missing or invalid session token")
        )
    )]
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

    /// Get ACL whitelist tokens.
    ///
    /// Returns all ACL tokens currently set for the authenticated AID's mailbox.
    #[utoipa::path(
        get,
        path = "/mailbox/acl",
        tag = "Mailbox",
        security(("bearerAuth" = [])),
        responses(
            (status = 200, description = "Current ACL tokens", body = AclTokensResponse),
            (status = 401, description = "Missing or invalid session token")
        )
    )]
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

    #[derive(serde::Deserialize, utoipa::IntoParams)]
    pub struct ChannelMessagesQuery {
        /// Start sequence number (0 = from beginning).
        s: Option<usize>,
    }

    /// List all channels the authenticated user is a member of.
    #[utoipa::path(
        get,
        path = "/channels",
        tag = "Channels",
        security(("bearerAuth" = [])),
        responses(
            (status = 200, description = "List of channels", body = Vec<crate::channel::Channel>),
            (status = 401, description = "Missing or invalid session token")
        )
    )]
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
    #[utoipa::path(
        get,
        path = "/channels/pending",
        tag = "Channels",
        security(("bearerAuth" = [])),
        responses(
            (status = 200, description = "Pending invites", body = Vec<PendingInviteItem>),
            (status = 401, description = "Missing or invalid session token")
        )
    )]
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
        let raw_invites = data.channel_handle.get_pending_invites(&session.aid).await;

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
    #[utoipa::path(
        get,
        path = "/channels/{said}",
        tag = "Channels",
        security(("bearerAuth" = [])),
        params(
            ("said" = String, Path, description = "Channel SAID")
        ),
        responses(
            (status = 200, description = "Channel metadata", body = crate::channel::Channel),
            (status = 401, description = "Missing or invalid session token / not a member"),
            (status = 404, description = "Channel not found")
        )
    )]
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
    #[utoipa::path(
        get,
        path = "/channels/{said}/messages",
        tag = "Channels",
        security(("bearerAuth" = [])),
        params(
            ("said" = String, Path, description = "Channel SAID"),
            ChannelMessagesQuery
        ),
        responses(
            (status = 200, description = "Channel messages", body = ChannelMessagesResponse),
            (status = 401, description = "Missing or invalid session token / not a member")
        )
    )]
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
            None => {
                Ok(HttpResponse::Ok().json(serde_json::json!({"last_sn": null, "messages": []})))
            }
        }
    }

    /// List all public broadcast channels on this instance (no auth).
    #[utoipa::path(
        get,
        path = "/broadcasts",
        tag = "Channels",
        responses(
            (status = 200, description = "Public broadcast channels", body = Vec<crate::channel::Channel>)
        )
    )]
    pub async fn list_broadcasts(
        data: web::Data<Arc<MessageBox>>,
    ) -> Result<HttpResponse, ApiError> {
        debug!("GET /broadcasts");
        let all = data.channel_handle.list_all().await;
        let broadcasts: Vec<_> = all
            .into_iter()
            .filter(|ch| ch.channel_type == crate::channel::ChannelType::Broadcast)
            .collect();
        debug!(count = broadcasts.len(), "GET /broadcasts -> 200");
        Ok(HttpResponse::Ok().json(broadcasts))
    }

    /// Get a broadcast channel by SAID (no auth).
    #[utoipa::path(
        get,
        path = "/broadcast/{said}",
        tag = "Channels",
        params(
            ("said" = String, Path, description = "Channel SAID"),
        ),
        responses(
            (status = 200, description = "Broadcast channel metadata", body = crate::channel::Channel),
            (status = 404, description = "Broadcast not found")
        )
    )]
    pub async fn get_broadcast(
        path: web::Path<String>,
        data: web::Data<Arc<MessageBox>>,
    ) -> Result<HttpResponse, ApiError> {
        let said = path.into_inner();
        debug!(said = %said, "GET /broadcast/{said}");

        let channel = data
            .channel_handle
            .get(&said)
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

    /// Get public broadcast messages by channel SAID (no auth required).
    #[utoipa::path(
        get,
        path = "/broadcast/{said}/messages",
        tag = "Channels",
        params(
            ("said" = String, Path, description = "Channel SAID"),
            ChannelMessagesQuery
        ),
        responses(
            (status = 200, description = "Broadcast messages", body = ChannelMessagesResponse),
            (status = 404, description = "Broadcast not found")
        )
    )]
    pub async fn get_broadcast_messages(
        path: web::Path<String>,
        query: web::Query<ChannelMessagesQuery>,
        data: web::Data<Arc<MessageBox>>,
    ) -> Result<HttpResponse, ApiError> {
        let said = path.into_inner();
        let from_sn = query.s.unwrap_or(0);
        debug!(said = %said, from_sn = from_sn, "GET /broadcast/{said}/messages");

        let channel = data
            .channel_handle
            .get(&said)
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
            None => {
                Ok(HttpResponse::Ok().json(serde_json::json!({"last_sn": null, "messages": []})))
            }
        }
    }

    /// EMQX HTTP authorization hook.
    /// Called by EMQX on each PUBLISH to check sender-level ACL.
    /// Only enforces ACL for publishes to `msg/inbox/{recipient_aid}`.
    #[derive(serde::Deserialize, utoipa::ToSchema)]
    pub struct MqttAuthzRequest {
        clientid: String,
        topic: String,
        action: String,
    }

    /// EMQX HTTP authorization hook for MQTT ACL enforcement.
    #[utoipa::path(
        post,
        path = "/mqtt/authz",
        tag = "MQTT",
        request_body = MqttAuthzRequest,
        responses(
            (status = 200, description = "Authorization result", body = MqttAuthzResult)
        )
    )]
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

    // -----------------------------------------------------------------------
    // Formal Mail federation endpoints
    // -----------------------------------------------------------------------

    /// Deliver mail envelope (server-to-server federation).
    ///
    /// Receive a CESR-signed mail envelope from a remote mesagkesto.
    /// No Bearer auth — sender authenticates via CESR signature in the envelope.
    #[utoipa::path(
        post,
        path = "/mail/deliver",
        tag = "Mail",
        request_body = serde_json::Value,
        responses(
            (status = 200, description = "Mail delivered, receipt returned", body = MailDeliveryReceipt),
            (status = 404, description = "No recipients found on this instance")
        )
    )]
    pub async fn mail_deliver(
        body: web::Json<serde_json::Value>,
        data: web::Data<Arc<MessageBox>>,
    ) -> Result<HttpResponse, ApiError> {
        debug!("POST /mail/deliver");

        let envelope = body.into_inner();

        // Extract and validate required fields
        let msg_id = envelope
            .get("id")
            .and_then(|v| v.as_str())
            .ok_or(ApiError::Unparsable)?;
        let from = envelope
            .get("from")
            .and_then(|v| v.as_str())
            .ok_or(ApiError::Unparsable)?;
        let recipients = envelope
            .get("to")
            .and_then(|v| v.as_array())
            .ok_or(ApiError::Unparsable)?;

        // TODO: Verify CESR signature in envelope.cesr_envelope against sender's KEL
        // For now, accept all deliveries (verification to be added in a follow-up)

        // Store for each local recipient
        let mut delivered_count = 0u32;
        for recipient_val in recipients {
            if let Some(recipient_aid) = recipient_val.as_str() {
                // Check if this recipient has a mailbox on this instance
                if data.mailbox_handle.exists(recipient_aid).await {
                    let envelope_str =
                        serde_json::to_string(&envelope).map_err(|_| ApiError::Unparsable)?;
                    data.storage_handle
                        .save_mail_message(recipient_aid, &envelope_str)
                        .await
                        .map_err(|e| {
                            ApiError::MessageboxError(MessageboxError::DbError(format!(
                                "Failed to store mail: {}",
                                e
                            )))
                        })?;
                    delivered_count += 1;
                }
            }
        }

        if delivered_count == 0 {
            debug!(from = %from, "POST /mail/deliver -> 404 (no local recipients)");
            return Ok(HttpResponse::NotFound().json(serde_json::json!({
                "error": "No recipients found on this instance"
            })));
        }

        // Build delivery receipt (signed by this mesagkesto instance)
        // TODO: CESR-sign the receipt with mesagkesto's own AID
        let receipt = serde_json::json!({
            "message_id": msg_id,
            "receipt_type": "delivery",
            "signer_aid": IdentifierPrefix::Basic(data.identifier.clone()).to_string(),
            "timestamp": chrono::Utc::now().to_rfc3339(),
            "cesr_signature": "" // TODO: sign with mesagkesto AID
        });

        debug!(from = %from, delivered = delivered_count, "POST /mail/deliver -> 200");
        Ok(HttpResponse::Ok().json(receipt))
    }

    /// Receive read receipt from remote mesagkesto (server-to-server).
    #[utoipa::path(
        post,
        path = "/mail/receipt",
        tag = "Mail",
        request_body = serde_json::Value,
        responses(
            (status = 200, description = "Receipt stored")
        )
    )]
    pub async fn mail_receipt(
        body: web::Json<serde_json::Value>,
        data: web::Data<Arc<MessageBox>>,
    ) -> Result<HttpResponse, ApiError> {
        debug!("POST /mail/receipt");

        let receipt = body.into_inner();
        let message_id = receipt
            .get("message_id")
            .and_then(|v| v.as_str())
            .ok_or(ApiError::Unparsable)?;
        let signer_aid = receipt
            .get("signer_aid")
            .and_then(|v| v.as_str())
            .ok_or(ApiError::Unparsable)?;

        // TODO: Verify CESR signature against signer's AID KEL

        // Store the receipt — the original sender can retrieve it
        // We need to know who the original sender was. The message_id should be enough
        // for the sender's client to poll for receipts.
        let receipt_str = serde_json::to_string(&receipt).map_err(|_| ApiError::Unparsable)?;
        data.storage_handle
            .save_mail_receipt(signer_aid, message_id, &receipt_str)
            .await
            .map_err(|e| {
                ApiError::MessageboxError(MessageboxError::DbError(format!(
                    "Failed to store receipt: {}",
                    e
                )))
            })?;

        debug!(msg_id = %message_id, signer = %signer_aid, "POST /mail/receipt -> 200");
        Ok(HttpResponse::Ok().finish())
    }

    /// GET /mail/messages — client polls for pending mail (authenticated).
    #[derive(serde::Deserialize, utoipa::IntoParams)]
    pub struct MailMessagesQuery {
        /// Sequence number to start from (0 = all).
        from_seq: Option<u64>,
    }

    /// Get pending mail messages (authenticated).
    #[utoipa::path(
        get,
        path = "/mail/messages",
        tag = "Mail",
        security(("bearerAuth" = [])),
        params(MailMessagesQuery),
        responses(
            (status = 200, description = "Mail messages", body = Vec<serde_json::Value>),
            (status = 401, description = "Missing or invalid session token")
        )
    )]
    pub async fn mail_get_messages(
        req: actix_web::HttpRequest,
        query: web::Query<MailMessagesQuery>,
        data: web::Data<Arc<MessageBox>>,
    ) -> Result<HttpResponse, ApiError> {
        debug!("GET /mail/messages");
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

        let from_seq = query.from_seq.unwrap_or(0);
        let messages = data
            .storage_handle
            .get_mail_messages(&session.aid, from_seq)
            .await
            .map_err(|e| {
                ApiError::MessageboxError(MessageboxError::DbError(format!(
                    "Failed to get mail: {}",
                    e
                )))
            })?;

        debug!(
            aid = %session.aid,
            count = messages.len(),
            "GET /mail/messages -> 200"
        );
        Ok(HttpResponse::Ok().json(messages))
    }

    /// Acknowledge receipt of a mail message.
    #[utoipa::path(
        delete,
        path = "/mail/messages/{seq}",
        tag = "Mail",
        security(("bearerAuth" = [])),
        params(
            ("seq" = u64, Path, description = "Mail message sequence number")
        ),
        responses(
            (status = 200, description = "Mail message deleted"),
            (status = 401, description = "Missing or invalid session token")
        )
    )]
    pub async fn mail_delete_message(
        req: actix_web::HttpRequest,
        path: web::Path<u64>,
        data: web::Data<Arc<MessageBox>>,
    ) -> Result<HttpResponse, ApiError> {
        let seq = path.into_inner();
        debug!("DELETE /mail/messages/{}", seq);
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

        data.storage_handle
            .delete_mail_message(&session.aid, seq)
            .await
            .map_err(|e| {
                ApiError::MessageboxError(MessageboxError::DbError(format!(
                    "Failed to delete mail: {}",
                    e
                )))
            })?;

        debug!(aid = %session.aid, seq = seq, "DELETE /mail/messages/{} -> 200", seq);
        Ok(HttpResponse::Ok().finish())
    }

    // -----------------------------------------------------------------------
    // Storage Vault endpoints
    // -----------------------------------------------------------------------

    /// Upload a content-addressed blob (authenticated).
    ///
    /// The SAID must match the SHA-256 hash of the content.
    #[utoipa::path(
        put,
        path = "/vault/{said}",
        tag = "Vault",
        security(("bearerAuth" = [])),
        params(
            ("said" = String, Path, description = "SHA-256 hash of the content (hex-encoded)")
        ),
        request_body(content = Vec<u8>, content_type = "application/octet-stream",
                     description = "Binary blob content"),
        responses(
            (status = 201, description = "Blob stored"),
            (status = 400, description = "SAID does not match content hash"),
            (status = 401, description = "Missing or invalid session token")
        )
    )]
    pub async fn vault_put(
        req: actix_web::HttpRequest,
        path: web::Path<String>,
        body: web::Bytes,
        data: web::Data<Arc<MessageBox>>,
    ) -> Result<HttpResponse, ApiError> {
        let said = path.into_inner();
        debug!("PUT /vault/{}", said);

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
        let _session = auth
            .validate_session(token)
            .await
            .ok_or(ApiError::Unauthorized)?;

        // Verify the SAID matches the content hash
        use sha2::{Digest, Sha256};
        let digest = Sha256::digest(&body);
        let hash = digest
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>();
        if hash != said {
            return Ok(HttpResponse::BadRequest().json(serde_json::json!({
                "error": "SAID does not match content hash",
                "expected": said,
                "actual": hash
            })));
        }

        data.storage_handle
            .vault_put(&said, &body)
            .await
            .map_err(|e| {
                ApiError::MessageboxError(MessageboxError::DbError(format!(
                    "Failed to store vault blob: {}",
                    e
                )))
            })?;

        debug!(said = %said, size = body.len(), "PUT /vault/{} -> 201", said);
        Ok(HttpResponse::Created().finish())
    }

    /// Download a blob by SAID.
    ///
    /// Publicly accessible — knowing the SAID is authorization (content-addressed).
    #[utoipa::path(
        get,
        path = "/vault/{said}",
        tag = "Vault",
        params(
            ("said" = String, Path, description = "SHA-256 hash of the content (hex-encoded)")
        ),
        responses(
            (status = 200, description = "Blob content", content_type = "application/octet-stream",
             body = Vec<u8>),
            (status = 404, description = "Blob not found")
        )
    )]
    pub async fn vault_get(
        path: web::Path<String>,
        data: web::Data<Arc<MessageBox>>,
    ) -> Result<HttpResponse, ApiError> {
        let said = path.into_inner();
        debug!("GET /vault/{}", said);

        let blob = data.storage_handle.vault_get(&said).await.map_err(|e| {
            ApiError::MessageboxError(MessageboxError::DbError(format!(
                "Failed to get vault blob: {}",
                e
            )))
        })?;

        match blob {
            Some(data) => {
                debug!(said = %said, size = data.len(), "GET /vault/{} -> 200", said);
                Ok(HttpResponse::Ok()
                    .content_type("application/octet-stream")
                    .body(data))
            }
            None => {
                debug!(said = %said, "GET /vault/{} -> 404", said);
                Ok(HttpResponse::NotFound().finish())
            }
        }
    }

    // --- Admin endpoints ---

    /// Validate that the request comes from the admin AID (via DauthZ session).
    async fn validate_admin(
        req: &actix_web::HttpRequest,
        data: &web::Data<Arc<MessageBox>>,
    ) -> Result<(), ApiError> {
        let auth = data
            .auth_handle
            .as_ref()
            .ok_or(ApiError::AuthNotConfigured)?;
        let admin_aid = data
            .admin_aid
            .as_ref()
            .ok_or(ApiError::Forbidden("admin not configured".to_string()))?;
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
        if session.aid != *admin_aid {
            return Err(ApiError::Forbidden(
                "only the admin AID can access this endpoint".to_string(),
            ));
        }
        Ok(())
    }

    #[derive(serde::Deserialize, utoipa::ToSchema)]
    pub struct CreateInviteBody {
        /// Optional human-readable label for the invite.
        label: Option<String>,
    }

    /// Create invitation token (admin only).
    #[utoipa::path(
        post,
        path = "/admin/invites",
        tag = "Admin",
        security(("bearerAuth" = [])),
        request_body = Option<CreateInviteBody>,
        responses(
            (status = 201, description = "Invite created", body = crate::registration::InviteToken),
            (status = 401, description = "Missing or invalid session token"),
            (status = 403, description = "Only admin AID can access this endpoint")
        )
    )]
    pub async fn admin_create_invite(
        req: actix_web::HttpRequest,
        data: web::Data<Arc<MessageBox>>,
        body: web::Json<Option<CreateInviteBody>>,
    ) -> Result<HttpResponse, ApiError> {
        validate_admin(&req, &data).await?;
        let label = body.into_inner().and_then(|b| b.label);
        let invite = data
            .registration_handle
            .create_invite(label)
            .await
            .map_err(ApiError::MessageboxError)?;
        Ok(HttpResponse::Created().json(invite))
    }

    /// List all active invite tokens (admin only).
    #[utoipa::path(
        get,
        path = "/admin/invites",
        tag = "Admin",
        security(("bearerAuth" = [])),
        responses(
            (status = 200, description = "Active invites", body = Vec<crate::registration::InviteToken>),
            (status = 401, description = "Missing or invalid session token"),
            (status = 403, description = "Only admin AID can access this endpoint")
        )
    )]
    pub async fn admin_list_invites(
        req: actix_web::HttpRequest,
        data: web::Data<Arc<MessageBox>>,
    ) -> Result<HttpResponse, ApiError> {
        validate_admin(&req, &data).await?;
        let invites = data.registration_handle.list_invites().await;
        Ok(HttpResponse::Ok().json(invites))
    }

    /// Revoke invitation token (admin only).
    #[utoipa::path(
        delete,
        path = "/admin/invites/{token}",
        tag = "Admin",
        security(("bearerAuth" = [])),
        params(
            ("token" = String, Path, description = "Invite token to revoke")
        ),
        responses(
            (status = 200, description = "Invite revoked"),
            (status = 401, description = "Missing or invalid session token"),
            (status = 403, description = "Only admin AID can access this endpoint"),
            (status = 404, description = "Token not found")
        )
    )]
    pub async fn admin_revoke_invite(
        req: actix_web::HttpRequest,
        path: web::Path<String>,
        data: web::Data<Arc<MessageBox>>,
    ) -> Result<HttpResponse, ApiError> {
        validate_admin(&req, &data).await?;
        let token = path.into_inner();
        let revoked = data.registration_handle.revoke_invite(token).await;
        if revoked {
            Ok(HttpResponse::Ok().json(serde_json::json!({"revoked": true})))
        } else {
            Ok(HttpResponse::NotFound().finish())
        }
    }

    #[derive(serde::Deserialize, utoipa::ToSchema)]
    pub struct AddWhitelistBody {
        /// AID to add to the registration whitelist.
        aid: String,
    }

    /// Add AID to registration whitelist (admin only).
    #[utoipa::path(
        post,
        path = "/admin/whitelist",
        tag = "Admin",
        security(("bearerAuth" = [])),
        request_body = AddWhitelistBody,
        responses(
            (status = 201, description = "AID added to whitelist"),
            (status = 401, description = "Missing or invalid session token"),
            (status = 403, description = "Only admin AID can access this endpoint")
        )
    )]
    pub async fn admin_add_whitelist(
        req: actix_web::HttpRequest,
        data: web::Data<Arc<MessageBox>>,
        body: web::Json<AddWhitelistBody>,
    ) -> Result<HttpResponse, ApiError> {
        validate_admin(&req, &data).await?;
        data.registration_handle
            .add_whitelist(body.into_inner().aid)
            .await
            .map_err(ApiError::MessageboxError)?;
        Ok(HttpResponse::Created().finish())
    }

    /// List whitelisted AIDs (admin only).
    #[utoipa::path(
        get,
        path = "/admin/whitelist",
        tag = "Admin",
        security(("bearerAuth" = [])),
        responses(
            (status = 200, description = "Whitelisted AIDs", body = Vec<String>),
            (status = 401, description = "Missing or invalid session token"),
            (status = 403, description = "Only admin AID can access this endpoint")
        )
    )]
    pub async fn admin_list_whitelist(
        req: actix_web::HttpRequest,
        data: web::Data<Arc<MessageBox>>,
    ) -> Result<HttpResponse, ApiError> {
        validate_admin(&req, &data).await?;
        let aids = data.registration_handle.list_whitelist().await;
        Ok(HttpResponse::Ok().json(aids))
    }

    /// Remove AID from whitelist (admin only).
    #[utoipa::path(
        delete,
        path = "/admin/whitelist/{aid}",
        tag = "Admin",
        security(("bearerAuth" = [])),
        params(
            ("aid" = String, Path, description = "AID to remove from whitelist")
        ),
        responses(
            (status = 200, description = "AID removed from whitelist"),
            (status = 401, description = "Missing or invalid session token"),
            (status = 403, description = "Only admin AID can access this endpoint"),
            (status = 404, description = "AID not found in whitelist")
        )
    )]
    pub async fn admin_remove_whitelist(
        req: actix_web::HttpRequest,
        path: web::Path<String>,
        data: web::Data<Arc<MessageBox>>,
    ) -> Result<HttpResponse, ApiError> {
        validate_admin(&req, &data).await?;
        let aid = path.into_inner();
        let removed = data.registration_handle.remove_whitelist(aid).await;
        if removed {
            Ok(HttpResponse::Ok().json(serde_json::json!({"removed": true})))
        } else {
            Ok(HttpResponse::NotFound().finish())
        }
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
    #[error("Forbidden: {0}")]
    Forbidden(String),
    #[error("Registration denied: {0}")]
    RegistrationDenied(String),
}

impl ResponseError for ApiError {
    fn status_code(&self) -> StatusCode {
        match self {
            ApiError::Unauthorized => StatusCode::UNAUTHORIZED,
            ApiError::AuthNotConfigured => StatusCode::NOT_FOUND,
            ApiError::Forbidden(_) => StatusCode::FORBIDDEN,
            ApiError::RegistrationDenied(_) => StatusCode::FORBIDDEN,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    fn error_response(&self) -> HttpResponse {
        HttpResponse::build(self.status_code()).body(self.to_string())
    }
}
