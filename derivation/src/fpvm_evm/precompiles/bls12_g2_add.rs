//! Contains the accelerated precompile for the BLS12-381 curve G2 Point Addition.
//!
//! BLS12-381 is introduced in [EIP-2537](https://eips.ethereum.org/EIPS/eip-2537).
//!
//! For constants and logic, see the [revm implementation].
//!
//! [revm implementation]: https://github.com/bluealloy/revm/blob/main/crates/precompile/src/bls12_381/g2_add.rs

use crate::fpvm_evm::precompiles::utils::precompile_run;
use crate::oracle::MemoryOracleClient;
use alloc::string::ToString;
use revm::precompile::{
    bls12_381,
    bls12_381_const::{G2_ADD_BASE_GAS_FEE, G2_ADD_INPUT_LENGTH},
    PrecompileError, PrecompileOutput, PrecompileResult,
};

/// Performs an FPVM-accelerated BLS12-381 G2 addition check.
///
/// Notice, there is no input size limit for this precompile.
/// See: <https://specs.optimism.io/protocol/isthmus/exec-engine.html#evm-changes>
pub(crate) fn fpvm_bls12_g2_add(
    input: &[u8],
    gas_limit: u64,
    oracle_reader: &MemoryOracleClient,
) -> PrecompileResult {
    if G2_ADD_BASE_GAS_FEE > gas_limit {
        return Err(PrecompileError::OutOfGas);
    }

    let input_len = input.len();
    if input_len != G2_ADD_INPUT_LENGTH {
        return Err(PrecompileError::Other(alloc::format!(
            "G2 addition input length should be {G2_ADD_INPUT_LENGTH} bytes, was {input_len}"
        )));
    }

    let result_data = kona_proof::block_on(precompile_run! {
        oracle_reader,
        &[bls12_381::g2_add::PRECOMPILE.address().as_slice(), &G2_ADD_BASE_GAS_FEE.to_be_bytes(), input]
    })
    .map_err(|e| PrecompileError::Other(e.to_string()))?;

    Ok(PrecompileOutput::new(
        G2_ADD_BASE_GAS_FEE,
        result_data.into(),
    ))
}
