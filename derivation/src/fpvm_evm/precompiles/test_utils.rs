//! Test utilities for accelerated precompiles.
#[cfg(test)]
pub mod test {

    use crate::oracle::MemoryOracleClient;
    use crate::types::Preimage;
    use alloc::boxed::Box;
    use alloc::sync::Arc;
    use alloc::vec;
    use alloc::vec::Vec;
    use alloy_primitives::{keccak256, Address, Bytes};
    use async_trait::async_trait;
    use kona_preimage::{
        errors::PreimageOracleResult, HintWriterClient, PreimageKey, PreimageKeyType,
        PreimageOracleClient,
    };
    use kona_proof::{Hint, HintType};
    use revm::precompile::PrecompileResult;

    /// Runs a test with a mock host that serves [`HintType::L1Precompile`] hints and preimages. The
    /// closure accepts the client's [`HintWriter`] and [`OracleReader`] as arguments.
    /// Executes a precompile on [`revm`].
    pub(crate) fn execute_native_precompile<T: Into<Bytes>>(
        address: Address,
        input: T,
        gas: u64,
    ) -> PrecompileResult {
        let precompiles = revm::handler::EthPrecompiles::default();
        let Some(precompile) = precompiles.precompiles.get(&address) else {
            panic!("Precompile not found");
        };
        precompile(&input.into(), gas)
    }

    #[derive(Clone, Debug, Default)]
    pub struct TestOracleReader {
        inner: Arc<spin::RwLock<MemoryOracleClient>>,
    }

    impl TestOracleReader {
        pub fn new() -> Self {
            Self {
                inner: Arc::new(spin::RwLock::new(MemoryOracleClient::default())),
            }
        }
    }

    #[async_trait]
    impl PreimageOracleClient for TestOracleReader {
        async fn get(&self, key: PreimageKey) -> PreimageOracleResult<Vec<u8>> {
            self.inner.read().get(key).await
        }

        async fn get_exact(&self, key: PreimageKey, buf: &mut [u8]) -> PreimageOracleResult<()> {
            self.inner.read().get_exact(key, buf).await
        }
    }

    #[async_trait]
    impl HintWriterClient for TestOracleReader {
        async fn write(&self, last_hint: &str) -> PreimageOracleResult<()> {
            let parsed_hint = last_hint.parse::<Hint<HintType>>().unwrap();
            if matches!(parsed_hint.ty, HintType::L1Precompile) {
                let address = Address::from_slice(&parsed_hint.data.as_ref()[..20]);
                let gas = u64::from_be_bytes(parsed_hint.data.as_ref()[20..28].try_into().unwrap());
                let input = parsed_hint.data[28..].to_vec();
                let input_hash = keccak256(parsed_hint.data.as_ref());

                let result = execute_native_precompile(address, input, gas).map_or_else(
                    |_| vec![0u8; 1],
                    |raw_res| {
                        let mut res = Vec::with_capacity(1 + raw_res.bytes.len());
                        res.push(0x01);
                        res.extend_from_slice(&raw_res.bytes);
                        res
                    },
                );

                let preimage_hash = Preimage::new(
                    PreimageKey::new_keccak256(*input_hash),
                    parsed_hint.data.into(),
                );
                let preimage_data = Preimage::new(
                    PreimageKey::new(*input_hash, PreimageKeyType::Precompile),
                    result,
                );

                let mut lock = self.inner.write();
                *lock = MemoryOracleClient::try_from(vec![preimage_hash, preimage_data]).unwrap();
                Ok(())
            } else {
                panic!("Unexpected hint type: {:?}", parsed_hint.ty);
            }
        }
    }
}
