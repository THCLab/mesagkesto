use std::{path::Path, sync::Arc};

use keri_sdk::{
    BasicPrefix, IdentifierPrefix, LocationScheme, SelfAddressingIdentifier, SelfSigningPrefix,
    Signature, Signer,
};
use keri_sdk::keri_core::{
    actor::prelude::{HashFunctionCode, SerializationFormats},
    error::Error,
    event_message::signature::get_signatures,
    query::reply_event::{ReplyEvent, ReplyRoute, SignedReply},
};

use actix::{Actor, Addr};
use tracing::{debug, info};

use crate::{
    acl::AclHandle, auth::AuthHandle, connection::ConnectionManager, db::Db,
    mailbox::MailboxHandle, notifier::NotifyHandle, oobis::OobiHandle,
    responses_store::ResponsesHandle, storage::StorageHandle, validate::ValidateHandle,
    verify::VerifyHandle, MessageboxError,
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
    pub connection_manager: Addr<ConnectionManager>,
}

impl MessageBox {
    pub async fn setup(
        db: Db,
        kel_path: &Path,
        oobi_path: &Path,
        watcher_oobi: LocationScheme,
        address: url::Url,
        seed: Option<String>,
        server_key: Option<String>,
        dauthz_state_dir: Option<&Path>,
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
        let response_handle = ResponsesHandle::new(db);
        let validator_handle = ValidateHandle::new(
            storage_handle.clone(),
            notify_handle,
            response_handle.clone(),
            acl_handle.clone(),
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
            connection_manager,
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
        let (_rest, parsed_data) =
            keri_sdk::cesrox::parse(input).map_err(|e| MessageboxError::Unparsable(e.to_string()))?;
        let data = match parsed_data.payload {
            keri_sdk::cesrox::payload::Payload::JSON(json) => json,
            keri_sdk::cesrox::payload::Payload::CBOR(_) => todo!(),
            keri_sdk::cesrox::payload::Payload::MGPK(_) => todo!(),
        };
        let signatures = parsed_data
            .attachments
            .into_iter()
            .map(|g| get_signatures(g))
            // This ignore errors while getting signatures
            .filter_map(|sig| {
                if let Ok(signature) = sig {
                    Some(signature)
                } else {
                    None
                }
            })
            .flatten();
        Ok((data, signatures))
    }
}
