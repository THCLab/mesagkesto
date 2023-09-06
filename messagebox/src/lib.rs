use messages::{Exchange, ExchangeRoute, MessageType, Query, QueryRoute};
use thiserror::Error;
use url::Url;

pub mod messagebox;
pub mod messagebox_listener;
pub mod messages;
pub mod notifier;
pub mod oobis;
pub mod queue;
pub mod storage;
pub mod validate;

#[derive(Error, Debug)]
pub enum MessageboxError {
    #[error("Can't communicate to cread agent: {0}")]
    Communication(String),
}

pub fn register_token(id: String, token: String) -> MessageType {
    let route = ExchangeRoute::SetFirebase { i: id, f: token };
    let exn = Exchange::new(
        said::sad::SerializationFormats::JSON,
        said::derivation::HashFunctionCode::Blake3_256.into(),
        route,
    );
    MessageType::Exn(exn)
}

pub fn forward_message(receiver: String, data: String) -> MessageType {
    let route = ExchangeRoute::Fwd {
        i: receiver,
        a: data,
    };
    let exn = Exchange::new(
        said::sad::SerializationFormats::JSON,
        said::derivation::HashFunctionCode::Blake3_256.into(),
        route,
    );
    MessageType::Exn(exn)
}

pub fn query_by_sn(receiver: String, sn: usize) -> MessageType {
    let route = QueryRoute::BySn { i: receiver, s: sn };
    let qry = Query::new(
        said::sad::SerializationFormats::JSON,
        said::derivation::HashFunctionCode::Blake3_256.into(),
        route,
    );
    MessageType::Qry(qry)
}

pub fn query_by_digest(receiver: String, digests: Vec<String>) -> MessageType {
    let route = QueryRoute::ByDigest {
        i: receiver,
        a: digests,
    };
    let qry = Query::new(
        said::sad::SerializationFormats::JSON,
        said::derivation::HashFunctionCode::Blake3_256.into(),
        route,
    );
    MessageType::Qry(qry)
}

pub fn send(message: &str, url: Url) -> Result<(), MessageboxError> {
    println!("Sending message to: {}", url);
    ureq::post(url.as_ref())
        .send_string(message)
        .map_err(|e| MessageboxError::Communication(e.to_string()))?;
    Ok(())
}
