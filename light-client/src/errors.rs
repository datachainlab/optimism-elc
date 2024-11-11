use kona_preimage::errors::InvalidPreimageKeyType;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    InvalidPreimageKeySize(usize),
    InvalidPreimageKey{
        #[from]
        source: InvalidPreimageKeyType,
        key: [u8;32]
    },
}