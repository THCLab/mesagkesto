use keri_controller::{error::ControllerError, IdentifierPrefix};
use keri_core::{actor::prelude::SelfAddressingIdentifier, keys::KeysError};
use thiserror::Error;
use url::Url;
use validate::ExchangeArguments;

pub mod messagebox;
pub mod messagebox_listener;
pub mod notifier;
pub mod oobis;
mod responses_store;
pub mod storage;
pub mod validate;
pub mod verify;

use crate::validate::MessageType;

#[derive(Error, Debug)]
pub enum MessageboxError {
    #[error("Can't communicate to: {0}")]
    Communication(String),
    #[error("Unknown message format: {0}")]
    UnknownMessage(String),
    #[error("Actor task has been killed")]
    KilledSender,
    #[error(transparent)]
    Controller(#[from] ControllerError),
    #[error(transparent)]
    Keri(#[from] keri_core::error::Error),
    #[error("Verification failed")]
    VerificationFailure,
    #[error("Kel event not in database")]
    MissingEvent(IdentifierPrefix, SelfAddressingIdentifier),
    #[error("Missing oobi")]
    MissingOobi,
    #[error("Can't parse oobi")]
    OobiParsingError,
    #[error("Can't parse seed")]
    SeedParsingError,
    #[error(transparent)]
    OobiError(ControllerError),
    #[error("Response not ready")]
    ResponseNotReady(SelfAddressingIdentifier),
    #[error("Unparsable: {0}")]
    Unparsable(String),
    #[error(transparent)]
    SigningError(#[from] KeysError),
}

pub fn register_token(id: String, token: String) -> MessageType {
    MessageType::Exn(ExchangeArguments::SetFirebase { i: id, f: token })
}

pub fn forward_message(receiver: String, data: String) -> MessageType {
    MessageType::Exn(ExchangeArguments::Fwd {
        i: receiver,
        a: data,
    })
}

pub fn query_by_sn(receiver: String, sn: usize) -> MessageType {
    MessageType::Qry(validate::QueryArguments::BySn { i: receiver, s: sn })
}

pub fn query_by_digest(receiver: String, digests: Vec<String>) -> MessageType {
    MessageType::Qry(validate::QueryArguments::ByDigest {
        i: receiver,
        d: digests,
    })
}

pub fn send(message: &str, url: Url) -> Result<(), MessageboxError> {
    println!("Sending message to: {}", url);
    ureq::post(url.as_ref())
        .send_string(message)
        .map_err(|e| MessageboxError::Communication(e.to_string()))?;
    Ok(())
}
