//! Contains the accelerated version of the `ecrecover` precompile.

use crate::host::eth::precompiles;
use alloc::string::ToString;
use alloy_primitives::{Address, Bytes};
use revm::{
    precompile::{u64_to_address, Error as PrecompileError, PrecompileWithAddress},
    primitives::{Precompile, PrecompileOutput, PrecompileResult},
};

const ECRECOVER_ADDRESS: Address = u64_to_address(1);

pub(crate) const FPVM_ECRECOVER: PrecompileWithAddress =
    PrecompileWithAddress(ECRECOVER_ADDRESS, Precompile::Standard(fpvm_ecrecover));

/// Performs an FPVM-accelerated `ecrecover` precompile call.
fn fpvm_ecrecover(input: &Bytes, gas_limit: u64) -> PrecompileResult {
    const ECRECOVER_BASE: u64 = 3_000;

    if ECRECOVER_BASE > gas_limit {
        return Err(PrecompileError::OutOfGas.into());
    }

    let result_data = precompiles::execute(ECRECOVER_ADDRESS, input.to_vec())
        .map(|result_data| result_data[1..].to_vec())
        .map_err(|e| PrecompileError::Other(e.to_string()))?;

    Ok(PrecompileOutput::new(ECRECOVER_BASE, result_data.into()))
}
