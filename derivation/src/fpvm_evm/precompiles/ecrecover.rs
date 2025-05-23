//! Contains the accelerated version of the `ecrecover` precompile.

use crate::fpvm_evm::precompiles::utils::precompile_run;
use alloc::string::ToString;
use alloy_primitives::Address;
use kona_preimage::{HintWriterClient, PreimageOracleClient};
use revm::precompile::{PrecompileError, PrecompileOutput, PrecompileResult};

/// Address of the `ecrecover` precompile.
pub(crate) const ECRECOVER_ADDR: Address = revm::precompile::u64_to_address(1);

/// Runs the FPVM-accelerated `ecrecover` precompile call.
pub(crate) fn fpvm_ec_recover<T: PreimageOracleClient + HintWriterClient>(
    input: &[u8],
    gas_limit: u64,
    oracle_reader: &T,
) -> PrecompileResult {
    const ECRECOVER_BASE: u64 = 3_000;

    if ECRECOVER_BASE > gas_limit {
        return Err(PrecompileError::OutOfGas);
    }

    let result_data = kona_proof::block_on(precompile_run! {
        oracle_reader,
        &[ECRECOVER_ADDR.as_slice(), &ECRECOVER_BASE.to_be_bytes(), input]
    })
    .map_err(|e| PrecompileError::Other(e.to_string()))
    .unwrap_or_default();

    Ok(PrecompileOutput::new(ECRECOVER_BASE, result_data.into()))
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::fpvm_evm::precompiles::test_utils::test::{
        execute_native_precompile, TestOracleReader,
    };
    use alloy_primitives::hex;

    #[test]
    fn test_accelerated_ecrecover() {
        let oracle = TestOracleReader::new();
        const EXPECTED_RESULT: [u8; 32] =
            hex!("0000000000000000000000007156526fbd7a3c72969b54f64e42c10fbb768c8a");

        let input = hex!(
                "456e9aea5e197a1f1af7a3e85a3212fa4049a3ba34c2289b4c860fc0b0c64ef3000000000000000000000000000000000000000000000000000000000000001c9242685bf161793cc25603c231bc2f568eb630ea16aa137d2664ac80388256084f8ae3bd7535248d0bd448298cc2e2071e56992d0774dc340c368ae950852ada"
            );
        let accelerated_result = fpvm_ec_recover(&input, u64::MAX, &oracle).unwrap();
        let native_result = execute_native_precompile(ECRECOVER_ADDR, input, u64::MAX).unwrap();

        assert_eq!(accelerated_result.bytes.as_ref(), EXPECTED_RESULT.as_ref());
        assert_eq!(accelerated_result.bytes, native_result.bytes);
        assert_eq!(accelerated_result.gas_used, native_result.gas_used);
    }

    #[test]
    fn test_accelerated_ecrecover_out_of_gas() {
        let oracle = TestOracleReader::new();
        let accelerated_result = fpvm_ec_recover(&[], 0, &oracle).unwrap_err();

        assert!(matches!(accelerated_result, PrecompileError::OutOfGas));
    }
}
