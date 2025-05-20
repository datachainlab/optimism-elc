#![no_std]
extern crate alloc;

pub mod derivation;
pub mod errors;
pub mod fpvm_evm;
pub mod oracle;
pub mod types;

pub use anyhow::Error;

const POSITION_FIELD_ELEMENT: usize = 72;
