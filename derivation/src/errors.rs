#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("invalid derivation {0}")]
    Kona(#[from] anyhow::Error),
}
