use std::{path::Path, sync::Arc};

use keri_sdk::keri_core::{
    error::Error,
    event_message::signature::get_signatures,
    query::reply_event::{ReplyEvent, ReplyRoute, SignedReply},
};
use keri_sdk::protocol::{HashFunctionCode, SerializationFormats};
use keri_sdk::{
    BasicPrefix, IdentifierPrefix, LocationScheme, SelfAddressingIdentifier, SelfSigningPrefix,
    Signature, Signer,
};

use actix::{Actor, Addr};
use tracing::{debug, info};

use crate::{
    acl::AclHandle,
    auth::AuthHandle,
    channel::ChannelHandle,
    connection::ConnectionManager,
    db::Db,
    mailbox::MailboxHandle,
    notifier::NotifyHandle,
    oobis::OobiHandle,
    registration::{RegistrationHandle, RegistrationMode},
    responses_store::ResponsesHandle,
    storage::StorageHandle,
    validate::ValidateHandle,
    verify::VerifyHandle,
    MessageboxError,
};

#[derive(Clone)]
pub struct MessageBox {
    signer: Arc<Signer>,
    pub identifier: BasicPrefix,
    pub public_address: url::Url,
    pub oobi_handle: OobiHandle,
    pub verify_handle: VerifyHandle,
    pub validator_handle: ValidateHandle,
    pub response_handle: ResponsesHandle,
    pub auth_handle: Option<AuthHandle>,
    pub mailbox_handle: MailboxHandle,
    pub acl_handle: AclHandle,
    pub channel_handle: ChannelHandle,
    pub storage_handle: StorageHandle,
    pub connection_manager: Addr<ConnectionManager>,
    pub jwt_secret: Option<String>,
    pub registration_handle: RegistrationHandle,
    pub admin_aid: Option<String>,
}

impl MessageBox {
    #[allow(clippy::too_many_arguments)]
    pub async fn setup(
        db: Db,
        kel_path: &Path,
        oobi_path: &Path,
        watcher_oobi: LocationScheme,
        address: url::Url,
        seed: Option<String>,
        server_key: Option<String>,
        dauthz_state_dir: Option<&Path>,
        jwt_secret: Option<String>,
        registration_mode: Option<&str>,
        admin_aid: Option<String>,
    ) -> Result<Self, MessageboxError> {
        debug!("Setting up messagebox");
        let signer = Arc::new(
            seed.map(|key| Signer::new_with_seed(&key.parse()?))
                .unwrap_or_else(|| Ok(Signer::new()))?,
        );
        let id = BasicPrefix::Ed25519NT(signer.public_key());
        debug!(identifier = ?id, "Messagebox identifier created");

        let scheme = address
            .scheme()
            .parse()
            .map_err(|_e| MessageboxError::Unparsable(address.scheme().to_string()))?;
        // save own oobi
        let loc_scheme =
            LocationScheme::new(IdentifierPrefix::Basic(id.clone()), scheme, address.clone());

        let reply = ReplyEvent::new_reply(
            ReplyRoute::LocScheme(loc_scheme.clone()),
            HashFunctionCode::Blake3_256,
            SerializationFormats::JSON,
        );
        let signed_reply = SignedReply::new_nontrans(
            reply.clone(),
            id.clone(),
            SelfSigningPrefix::Ed25519Sha512(signer.sign(reply.encode()?)?),
        );
        debug!("Signed own OOBI");

        let notify_handle = if let Some(key) = server_key {
            tracing::info!("Firebase server key configured");
            NotifyHandle::new(key, db.clone())
        } else {
            todo!("Firebase server_key is mandatory for now")
        };
        let storage_handle = StorageHandle::new(db.clone(), notify_handle.clone());
        let oobi_handle = OobiHandle::new(oobi_path);
        oobi_handle.register(vec![signed_reply]).await;
        info!("Own OOBI registered");

        let mailbox_handle = MailboxHandle::new(db.clone());
        let acl_handle = AclHandle::new(db.clone());
        let channel_handle = ChannelHandle::new(db.clone());
        let connection_manager = ConnectionManager::new().start();
        let auth_handle = if let Some(auth_dir) = dauthz_state_dir {
            let service_aid = IdentifierPrefix::Basic(id.clone()).to_string();
            let service_oobi = address.to_string();
            debug!(dauthz_dir = %auth_dir.display(), "Initializing DauthZ authentication");
            Some(AuthHandle::new(
                auth_dir,
                &service_aid,
                &service_oobi,
                db.clone(),
                signer.clone(),
                id.clone(),
            )?)
        } else {
            debug!("DauthZ authentication disabled (no state directory)");
            None
        };
        let reg_mode = RegistrationMode::from_str_config(registration_mode);
        let registration_handle = RegistrationHandle::new(db.clone(), reg_mode);

        // Auto-provision admin mailbox if admin_aid is configured
        if let Some(ref admin) = admin_aid {
            info!(admin_aid = %admin, "Auto-provisioning admin mailbox");
            let _ = mailbox_handle.provision(admin.clone()).await;
            let _ = mailbox_handle.activate(admin.clone()).await;
        }

        let response_handle = ResponsesHandle::new(db);
        let validator_handle = ValidateHandle::new(
            storage_handle.clone(),
            notify_handle,
            response_handle.clone(),
            acl_handle.clone(),
            channel_handle.clone(),
        );
        debug!("Initializing verify handle");
        let verify_handle =
            VerifyHandle::new(kel_path, watcher_oobi, validator_handle.clone()).await?;

        info!("Messagebox setup completed successfully");
        Ok(Self {
            public_address: address,
            signer,
            identifier: id,
            oobi_handle,
            validator_handle,
            verify_handle,
            response_handle,
            auth_handle,
            mailbox_handle,
            acl_handle,
            channel_handle,
            storage_handle,
            connection_manager,
            jwt_secret,
            registration_handle,
            admin_aid,
        })
    }

    pub async fn process_message(&self, body: String) -> Result<Option<String>, MessageboxError> {
        debug!(body_len = body.len(), "Processing incoming message");
        let (data, signatures) = Self::split_cesr_stream(body.as_bytes())?;
        let payload_str =
            String::from_utf8(data).map_err(|e| MessageboxError::Unparsable(e.to_string()))?;
        let sig_vec: Vec<_> = signatures.collect();
        debug!(sig_count = sig_vec.len(), "Message signatures parsed");

        match self.verify_handle.verify(&payload_str, sig_vec).await {
            Ok(sender_id) => {
                let sender_aid_str = sender_id.as_ref().map(|id| id.to_string());
                info!(sender = ?sender_aid_str, "Message verified successfully, validating");
                self.validator_handle
                    .validate(payload_str, sender_aid_str)
                    .await
            }
            Err(e) => {
                tracing::warn!(error = %e, "Message verification failed");
                Err(e)
            }
        }
    }

    pub async fn resolve_oobi(&self, oobi: String) -> Result<(), MessageboxError> {
        debug!(oobi = %oobi, "Resolving OOBI");
        self.verify_handle.resolve_oobi(oobi).await
    }

    /// Resolve an OOBI that may be a single object or a JSON array of OOBIs.
    /// Each entry in the array is resolved individually.
    pub async fn resolve_oobi_multi(&self, oobi_str: &str) -> Result<(), MessageboxError> {
        // Try parsing as array first
        if let Ok(oobis) = serde_json::from_str::<Vec<serde_json::Value>>(oobi_str) {
            for oobi_val in oobis {
                let single = serde_json::to_string(&oobi_val)
                    .map_err(|e| MessageboxError::Unparsable(e.to_string()))?;
                self.verify_handle.resolve_oobi(single).await?;
            }
            Ok(())
        } else {
            // Single OOBI object
            self.verify_handle.resolve_oobi(oobi_str.to_string()).await
        }
    }

    pub fn oobi(&self) -> LocationScheme {
        LocationScheme::new(
            IdentifierPrefix::Basic(self.identifier.clone()),
            keri_sdk::keri_core::oobi::Scheme::Http,
            self.public_address.clone(),
        )
    }

    // Helper function to get location of given id, wrap it into Reply event and sign
    pub async fn get_loc_scheme_for_id(
        &self,
        eid: &IdentifierPrefix,
    ) -> Result<Option<Vec<SignedReply>>, Error> {
        let oobis = self.oobi_handle.get_location(eid.clone()).await;
        oobis
            .map(|oobis_to_sign| -> Result<_, Error> {
                oobis_to_sign
                    .iter()
                    .map(|oobi_to_sing| -> Result<_, Error> {
                        let signature = self.signer.sign(oobi_to_sing.encode()?)?;
                        Ok(SignedReply::new_nontrans(
                            oobi_to_sing.clone(),
                            self.identifier.clone(),
                            SelfSigningPrefix::Ed25519Sha512(signature),
                        ))
                    })
                    .collect()
            })
            .transpose()
    }

    pub async fn get_responses(&self, sai: SelfAddressingIdentifier) -> Option<String> {
        self.response_handle.get_by_digest(sai).await
    }

    pub fn split_cesr_stream(
        input: &[u8],
    ) -> Result<(Vec<u8>, impl Iterator<Item = Signature>), MessageboxError> {
        let msg = keri_sdk::keri_core::event_message::cesr_adapter::parse_cesr_stream(input)
            .map_err(|e| MessageboxError::Unparsable(e.to_string()))?;
        let data = match msg.payload {
            keri_sdk::cesrox::payload::Payload::JSON(json) => json,
            keri_sdk::cesrox::payload::Payload::CBOR(_) => todo!(),
            keri_sdk::cesrox::payload::Payload::MGPK(_) => todo!(),
        };
        let signatures = msg
            .attachments
            .into_iter()
            .map(get_signatures)
            .filter_map(|sig| sig.ok())
            .flatten();
        Ok((data, signatures))
    }
}
