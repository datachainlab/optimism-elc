//! Contains the accelerated precompile for the BLS12-381 curve.
//!
//! BLS12-381 is introduced in [EIP-2537](https://eips.ethereum.org/EIPS/eip-2537).
//!
//! For constants and logic, see the [revm implementation].
//!
//! [revm implementation]: https://github.com/bluealloy/revm/blob/main/crates/precompile/src/bls12_381/pairing.rs

use crate::fpvm_evm::precompiles::utils::precompile_run;
use alloc::string::ToString;
use kona_preimage::{HintWriterClient, PreimageOracleClient};
use revm::precompile::{
    bls12_381,
    bls12_381_const::{PAIRING_INPUT_LENGTH, PAIRING_MULTIPLIER_BASE, PAIRING_OFFSET_BASE},
    PrecompileError, PrecompileOutput, PrecompileResult,
};

/// The max pairing size for BLS12-381 input given a 20M gas limit.
const BLS12_MAX_PAIRING_SIZE_ISTHMUS: usize = 235_008;

/// Performs an FPVM-accelerated BLS12-381 pairing check.
pub(crate) fn fpvm_bls12_pairing<T: PreimageOracleClient + HintWriterClient>(
    input: &[u8],
    gas_limit: u64,
    oracle_reader: &T,
) -> PrecompileResult {
    let input_len = input.len();

    if input_len > BLS12_MAX_PAIRING_SIZE_ISTHMUS {
        return Err(PrecompileError::Other(alloc::format!(
            "Pairing input length must be at most {}",
            BLS12_MAX_PAIRING_SIZE_ISTHMUS
        )));
    }

    if input_len % PAIRING_INPUT_LENGTH != 0 {
        return Err(PrecompileError::Other(alloc::format!(
            "Pairing input length should be multiple of {PAIRING_INPUT_LENGTH}, was {input_len}"
        )));
    }

    let k = input_len / PAIRING_INPUT_LENGTH;
    let required_gas: u64 = PAIRING_MULTIPLIER_BASE * k as u64 + PAIRING_OFFSET_BASE;
    if required_gas > gas_limit {
        return Err(PrecompileError::OutOfGas);
    }

    let result_data = kona_proof::block_on(precompile_run! {
        oracle_reader,
        &[bls12_381::pairing::PRECOMPILE.address().as_slice(), &required_gas.to_be_bytes(), input]
    })
    .map_err(|e| PrecompileError::Other(e.to_string()))?;

    Ok(PrecompileOutput::new(required_gas, result_data.into()))
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::fpvm_evm::precompiles::test_utils::test::execute_native_precompile;
    use crate::fpvm_evm::precompiles::test_utils::test::TestOracleReader;
    use alloy_primitives::hex;

    #[test]
    fn test_accelerated_bls12_381_pairing() {
        let oracle = TestOracleReader::new();
        // https://github.com/ethereum/execution-spec-tests/blob/a1c4eeff347a64ad6c5aedd51314d4ffc067346b/tests/prague/eip2537_bls_12_381_precompiles/vectors/pairing_check_bls.json
        let input = hex!("000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");
        let expected = hex!("0000000000000000000000000000000000000000000000000000000000000001");

        let accelerated_result = fpvm_bls12_pairing(&input, 70300, &oracle).unwrap();
        let native_result =
            execute_native_precompile(*bls12_381::pairing::PRECOMPILE.address(), input, 70300)
                .unwrap();

        assert_eq!(accelerated_result.bytes.as_ref(), expected.as_ref());
        assert_eq!(accelerated_result.bytes, native_result.bytes);
        assert_eq!(accelerated_result.gas_used, native_result.gas_used);
    }

    #[test]
    fn test_accelerated_bls12_381_pairing_bad_input_len_isthmus() {
        let oracle = TestOracleReader::new();
        let accelerated_result =
            fpvm_bls12_pairing(&[0u8; BLS12_MAX_PAIRING_SIZE_ISTHMUS + 1], 0, &oracle).unwrap_err();
        assert!(matches!(accelerated_result, PrecompileError::Other(_)));
    }

    #[test]
    fn test_accelerated_bls12_381_pairing_bad_input_len() {
        let oracle = TestOracleReader::new();
        let accelerated_result =
            fpvm_bls12_pairing(&[0u8; PAIRING_INPUT_LENGTH - 1], 0, &oracle).unwrap_err();
        assert!(matches!(accelerated_result, PrecompileError::Other(_)));
    }

    #[test]
    fn test_accelerated_bls12_381_pairing_bad_gas_limit() {
        let oracle = TestOracleReader::new();
        let accelerated_result =
            fpvm_bls12_pairing(&[0u8; PAIRING_INPUT_LENGTH], 0, &oracle).unwrap_err();
        assert!(matches!(accelerated_result, PrecompileError::OutOfGas));
    }
}
