use std::{path::Path, sync::Arc};

use keri::{
    actor::prelude::{HashFunctionCode, SerializationFormats},
    error::Error,
    oobi::LocationScheme,
    prefix::{BasicPrefix, IdentifierPrefix, SelfSigningPrefix},
    query::reply_event::{ReplyEvent, ReplyRoute, SignedReply},
    signer::Signer,
};

use crate::{
    notifier::NotifyHandle, oobis::OobiHandle, queue::QueueHandle, storage::StorageHandle,
    validate::ValidateHandle,
};

#[derive(Clone)]
pub struct MessageBox {
    signer: Arc<Signer>,
    pub identifier: BasicPrefix,
    pub public_address: url::Url,
    pub queue: QueueHandle,
    pub oobi_handle: OobiHandle,
}

impl MessageBox {
    pub async fn setup(
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
        let validator_handle = ValidateHandle::new(storage_handle.clone(), notify_handle);
        let queue = QueueHandle::new(validator_handle);
        Ok(Self {
            public_address: address,
            signer,
            identifier: id,
            oobi_handle,
            queue,
        })
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
}
