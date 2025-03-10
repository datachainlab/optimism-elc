#![no_std]
extern crate alloc;

// see kona/host
pub mod host;

pub mod derivation;
pub mod errors;
pub mod oracle;
pub mod types;

pub use anyhow::Error;

pub const POSITION_FIELD_ELEMENT: usize = 72;
