use alloy_primitives::B256;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("invalid derivation {0}")]
    Kona(#[from] anyhow::Error),
    #[error("invalid claim actual={0}, expected={1}")]
    InvalidClaim(B256, B256)
}
