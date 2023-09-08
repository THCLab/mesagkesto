use thiserror::Error;
use url::Url;
use validate::ExchangeArguments;

pub mod messagebox;
pub mod messagebox_listener;
pub mod notifier;
pub mod oobis;
pub mod storage;
pub mod validate;
use crate::validate::MessageType;

#[derive(Error, Debug)]
pub enum MessageboxError {
    #[error("Can't communicate to cread agent: {0}")]
    Communication(String),
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
