use std::{path::Path, sync::Arc};

use keri::{
    actor::prelude::{HashFunctionCode, SerializationFormats},
    error::Error,
    event_message::signature::{get_signatures, Signature},
    oobi::LocationScheme,
    prefix::{BasicPrefix, IdentifierPrefix, SelfSigningPrefix},
    query::reply_event::{ReplyEvent, ReplyRoute, SignedReply},
    signer::Signer,
};
use said::SelfAddressingIdentifier;

use crate::{
    notifier::NotifyHandle, oobis::OobiHandle, responses_store::ResponsesHandle,
    storage::StorageHandle, validate::ValidateHandle, verify::VerifyHandle, MessageboxError,
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
}

impl MessageBox {
    pub async fn setup(
        kel_path: &Path,
        oobi_path: &Path,
        address: url::Url,
        seed: Option<String>,
        server_key: Option<String>,
    ) -> Result<Self, Error> {
        let signer = Arc::new(
            seed.map(|key| Signer::new_with_seed(&key.parse()?))
                .unwrap_or_else(|| Ok(Signer::new()))?,
        );
        let id = BasicPrefix::Ed25519NT(signer.public_key());
        // save own oobi
        let loc_scheme = LocationScheme::new(
            IdentifierPrefix::Basic(id.clone()),
            address.scheme().parse().unwrap(),
            address.clone(),
        );

        let reply = ReplyEvent::new_reply(
            ReplyRoute::LocScheme(loc_scheme),
            HashFunctionCode::Blake3_256,
            SerializationFormats::JSON,
        )
        .unwrap();
        let signed_reply = SignedReply::new_nontrans(
            reply.clone(),
            id.clone(),
            SelfSigningPrefix::Ed25519Sha512(signer.sign(reply.encode().unwrap()).unwrap()),
        );
        let notify_handle = if let Some(key) = server_key {
            println!("Firebase server key set: {}", &key);
            NotifyHandle::new(key)
        } else {
            todo!("Firebase server_key is mandatory for now")
        };
        let storage_handle = StorageHandle::new(notify_handle.clone());
        let oobi_handle = OobiHandle::new(oobi_path);
        oobi_handle.register(vec![signed_reply]).await;
        let response_handle = ResponsesHandle::new();
        let validator_handle = ValidateHandle::new(
            storage_handle.clone(),
            notify_handle,
            response_handle.clone(),
        );
        let verify_handle = VerifyHandle::new(kel_path, validator_handle.clone()).await;
        Ok(Self {
            public_address: address,
            signer,
            identifier: id,
            oobi_handle,
            validator_handle,
            verify_handle,
            response_handle,
        })
    }

    pub async fn process_message(&self, body: String) -> Result<Option<String>, MessageboxError> {
        let (data, signatures) = Self::split_cesr_stream(body.as_bytes());
        match self
            .verify_handle
            .verify(std::str::from_utf8(&data).unwrap(), signatures.collect())
            .await
        {
            Ok(_) => {
                self.validator_handle
                    .validate(String::from_utf8(data).unwrap())
                    .await
            }
            // Err(MessageboxError::MissingEvent(id, dig )) => {

            // },
            Err(e) => Err(e),
        }
    }

    pub async fn resolve_oobi(&self, oobi: String) -> Result<(), MessageboxError> {
        self.verify_handle.resolve_oobi(oobi).await
    }

    pub fn oobi(&self) -> LocationScheme {
        LocationScheme::new(
            IdentifierPrefix::Basic(self.identifier.clone()),
            keri::oobi::Scheme::Http,
            self.public_address.clone(),
        )
    }

    // Helper function to get location of given id, wrap it into Reply event and sign
    pub async fn get_loc_scheme_for_id(
        &self,
        eid: &IdentifierPrefix,
    ) -> Result<Option<Vec<SignedReply>>, Error> {
        let oobis = self.oobi_handle.get_location(eid.clone()).await;
        Ok(oobis.map(|oobis_to_sign| {
            oobis_to_sign
                .iter()
                .map(|oobi_to_sing| {
                    let signature = self.signer.sign(oobi_to_sing.encode().unwrap()).unwrap();
                    SignedReply::new_nontrans(
                        oobi_to_sing.clone(),
                        self.identifier.clone(),
                        SelfSigningPrefix::Ed25519Sha512(signature),
                    )
                })
                .collect()
        }))
    }

    pub async fn get_responses(&self, sai: SelfAddressingIdentifier) -> Option<String> {
        self.response_handle.get_by_digest(sai).await
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
}
