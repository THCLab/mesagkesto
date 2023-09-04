use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Something is wrong")]
    WrongError,
}