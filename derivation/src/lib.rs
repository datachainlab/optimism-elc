#![no_std]
#![allow(clippy::result_large_err)]
extern crate alloc;

pub mod derivation;
pub mod errors;
pub mod oracle;
pub mod types;

const POSITION_FIELD_ELEMENT: usize = 72;
