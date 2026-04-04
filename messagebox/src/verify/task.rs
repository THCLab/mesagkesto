use keri_sdk::{IdentifierPrefix, Signature};
use tokio::sync::oneshot::Sender;

use crate::MessageboxError;

#[derive(Debug)]
pub enum VerificationTask {
    Verify(
        String,
        Vec<Signature>,
        Sender<Result<Option<IdentifierPrefix>, MessageboxError>>,
    ),
    Find(IdentifierPrefix),
    Reverify(IdentifierPrefix),
}
