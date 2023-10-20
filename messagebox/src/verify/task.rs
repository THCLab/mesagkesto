use controller::IdentifierPrefix;
use tokio::sync::oneshot::Sender;

use crate::MessageboxError;

#[derive(Debug)]
pub enum VerificationTask {
    Verify(String, Sender<Result<bool, MessageboxError>>),
    Find(IdentifierPrefix),
    Reverify(IdentifierPrefix),
}
