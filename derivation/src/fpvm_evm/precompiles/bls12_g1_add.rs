//! Contains the accelerated precompile for the BLS12-381 curve G1 Point Addition.
//!
//! BLS12-381 is introduced in [EIP-2537](https://eips.ethereum.org/EIPS/eip-2537).
//!
//! For constants and logic, see the [revm implementation].
//!
//! [revm implementation]: https://github.com/bluealloy/revm/blob/main/crates/precompile/src/bls12_381/g1_add.rs

use crate::fpvm_evm::precompiles::utils::precompile_run;
use alloc::string::ToString;
use kona_preimage::{HintWriterClient, PreimageOracleClient};
use revm::precompile::{
    bls12_381,
    bls12_381_const::{G1_ADD_BASE_GAS_FEE, G1_ADD_INPUT_LENGTH},
    PrecompileError, PrecompileOutput, PrecompileResult,
};

/// Performs an FPVM-accelerated BLS12-381 G1 addition check.
///
/// Notice, there is no input size limit for this precompile.
/// See: <https://specs.optimism.io/protocol/isthmus/exec-engine.html#evm-changes>
pub(crate) fn fpvm_bls12_g1_add<T: PreimageOracleClient + HintWriterClient>(
    input: &[u8],
    gas_limit: u64,
    oracle_reader: &T,
) -> PrecompileResult {
    if G1_ADD_BASE_GAS_FEE > gas_limit {
        return Err(PrecompileError::OutOfGas);
    }

    let input_len = input.len();
    if input_len != G1_ADD_INPUT_LENGTH {
        return Err(PrecompileError::Other(alloc::format!(
            "G1 addition input length should be {G1_ADD_INPUT_LENGTH} bytes, was {input_len}"
        )));
    }

    let result_data = kona_proof::block_on(precompile_run! {
        oracle_reader,
        &[bls12_381::g1_add::PRECOMPILE.address().as_slice(), &G1_ADD_BASE_GAS_FEE.to_be_bytes(), input]
    })
    .map_err(|e| PrecompileError::Other(e.to_string()))?;

    Ok(PrecompileOutput::new(
        G1_ADD_BASE_GAS_FEE,
        result_data.into(),
    ))
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::fpvm_evm::precompiles::test_utils::{
        execute_native_precompile, TestOracleReader,
    };

    #[test]
    fn test_accelerated_bls12_381_g1_add() {
        let oracle = TestOracleReader::new();

        // G1.INF + G1.INF = G1.INF
        let input = [0u8; G1_ADD_INPUT_LENGTH];
        let accelerated_result = fpvm_bls12_g1_add(&input, u64::MAX, &oracle).unwrap();
        let native_result =
            execute_native_precompile(*bls12_381::g1_add::PRECOMPILE.address(), input, u64::MAX)
                .unwrap();

        assert_eq!(accelerated_result.bytes, native_result.bytes);
        assert_eq!(accelerated_result.gas_used, native_result.gas_used);
    }

    #[test]
    fn test_accelerated_bls12_381_g1_add_bad_input_len() {
        let oracle = TestOracleReader::new();
        let accelerated_result = fpvm_bls12_g1_add(&[], u64::MAX, &oracle).unwrap_err();
        assert!(matches!(accelerated_result, PrecompileError::Other(_)));
    }

    #[test]
    fn test_accelerated_bls12_381_g1_add_bad_gas_limit() {
        let oracle = TestOracleReader::new();
        let accelerated_result = fpvm_bls12_g1_add(&[], 0, &oracle).unwrap_err();
        assert!(matches!(accelerated_result, PrecompileError::OutOfGas));
    }
}
