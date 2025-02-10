//! Contains the accelerated version of the KZG point evaluation precompile.

use crate::host::eth::precompiles;
use alloc::string::ToString;
use alloy_primitives::{Address, Bytes};
use revm::{
    precompile::{u64_to_address, Error as PrecompileError, PrecompileWithAddress},
    primitives::{Precompile, PrecompileOutput, PrecompileResult},
};

const POINT_EVAL_ADDRESS: Address = u64_to_address(0x0A);

pub(crate) const FPVM_KZG_POINT_EVAL: PrecompileWithAddress = PrecompileWithAddress(
    POINT_EVAL_ADDRESS,
    Precompile::Standard(fpvm_kzg_point_eval),
);

/// Performs an FPVM-accelerated KZG point evaluation precompile call.
fn fpvm_kzg_point_eval(input: &Bytes, gas_limit: u64) -> PrecompileResult {
    const GAS_COST: u64 = 50_000;

    if gas_limit < GAS_COST {
        return Err(PrecompileError::OutOfGas.into());
    }

    if input.len() != 192 {
        return Err(PrecompileError::BlobInvalidInputLength.into());
    }

    let result_data = precompiles::execute(POINT_EVAL_ADDRESS, input.to_vec())
        .map(|result_data| result_data[1..].to_vec())
        .map_err(|e| PrecompileError::Other(e.to_string()))?;

    Ok(PrecompileOutput::new(GAS_COST, result_data.into()))
}
