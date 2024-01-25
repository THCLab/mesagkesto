use keri_controller::IdentifierPrefix;
use keri_core::event_message::signature::Signature;
use tokio::sync::oneshot::Sender;

use crate::MessageboxError;

#[derive(Debug)]
pub enum VerificationTask {
    Verify(String, Vec<Signature>, Sender<Result<(), MessageboxError>>),
    Find(IdentifierPrefix),
    Reverify(IdentifierPrefix),
}
