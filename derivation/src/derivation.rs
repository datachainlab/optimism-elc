use crate::errors;
use alloc::sync::Arc;
use alloy_consensus::Header;
use alloy_primitives::{Sealed, B256};
use anyhow::Result;
use core::fmt::Debug;
use kona_driver::Driver;
use kona_executor::TrieDBProvider;
use kona_preimage::{CommsClient, PreimageKey};
use kona_proof::errors::OracleProviderError;
use kona_proof::{
    executor::KonaExecutor,
    l1::{OracleBlobProvider, OracleL1ChainProvider, OraclePipeline},
    l2::OracleL2ChainProvider,
    sync::new_pipeline_cursor,
    BootInfo, FlushableCache, HintType,
};
use kona_genesis::RollupConfig;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Derivation {
    pub l1_head_hash: B256,
    pub agreed_l2_output_root: B256,
    pub l2_output_root: B256,
    pub l2_block_number: u64,
}

impl Derivation {
    pub fn new(
        l1_head_hash: B256,
        agreed_l2_output_root: B256,
        l2_output_root: B256,
        l2_block_number: u64,
    ) -> Self {
        Derivation {
            l1_head_hash,
            agreed_l2_output_root,
            l2_output_root,
            l2_block_number,
        }
    }

    pub fn verify<T: CommsClient + Send + Sync + FlushableCache + Debug>(
        &self,
        chain_id: u64,
        rollup_config: &RollupConfig,
        oracle: T,
    ) -> Result<Header> {
        kona_proof::block_on(self.run(chain_id, rollup_config, oracle))
    }

    async fn run<T: CommsClient + Send + Sync + FlushableCache + Debug>(
        &self,
        chain_id: u64,
        rollup_config: &RollupConfig,
        oracle: T,
    ) -> Result<Header> {
        let boot = &BootInfo {
            l1_head: self.l1_head_hash,
            agreed_l2_output_root: self.agreed_l2_output_root,
            claimed_l2_output_root: self.l2_output_root,
            claimed_l2_block_number: self.l2_block_number,
            chain_id,
            rollup_config: rollup_config.clone(),
        };
        let rollup_config = Arc::new(boot.rollup_config.clone());
        let safe_head_hash = fetch_safe_head_hash(&oracle, boot.agreed_l2_output_root).await?;
        let oracle = Arc::new(oracle);
        let mut l1_provider = OracleL1ChainProvider::new(boot.l1_head, oracle.clone());
        let mut l2_provider =
            OracleL2ChainProvider::new(safe_head_hash, rollup_config.clone(), oracle.clone());
        let beacon = OracleBlobProvider::new(oracle.clone());

        let safe_head = l2_provider
            .header_by_hash(safe_head_hash)
            .map(|header| Sealed::new_unchecked(header, safe_head_hash))?;

        let cursor = new_pipeline_cursor(
            rollup_config.as_ref(),
            safe_head,
            &mut l1_provider,
            &mut l2_provider,
        )
        .await?;
        l2_provider.set_cursor(cursor.clone());

        let pipeline = OraclePipeline::new(
            rollup_config.clone(),
            cursor.clone(),
            oracle.clone(),
            beacon,
            l1_provider.clone(),
            l2_provider.clone(),
        ).await?;

        let executor = KonaExecutor::new(
            rollup_config.as_ref(),
            l2_provider.clone(),
            l2_provider,
            // https://github.com/op-rs/kona/blob/660d41d0e4100fb0a73363a5fa057287e6882dfd/bin/host/src/single/orchestrator.rs#L86
            None,
            None,
        );
        let mut driver = Driver::new(cursor, executor, pipeline);

        // Run the derivation pipeline until we are able to produce the output root of the claimed
        // L2 block.
        let (_, output_root) = driver
            .advance_to_target(&boot.rollup_config, Some(boot.claimed_l2_block_number))
            .await?;

        ////////////////////////////////////////////////////////////////
        //                          EPILOGUE                          //
        ////////////////////////////////////////////////////////////////

        if output_root != boot.claimed_l2_output_root {
            return Err(
                errors::Error::InvalidClaim(output_root, boot.claimed_l2_output_root).into(),
            );
        }

        let read = driver.cursor.read();
        let header = read.l2_safe_head_header().clone().unseal();
        Ok(header)
    }
}

pub async fn fetch_safe_head_hash<O>(
    caching_oracle: &O,
    agreed_l2_output_root: B256,
) -> Result<B256, OracleProviderError>
where
    O: CommsClient,
{
    let mut output_preimage = [0u8; 128];
    HintType::StartingL2Output
        .with_data(&[agreed_l2_output_root.as_ref()])
        .send(caching_oracle)
        .await?;
    caching_oracle
        .get_exact(PreimageKey::new_keccak256(*agreed_l2_output_root), output_preimage.as_mut())
        .await?;

    output_preimage[96..128].try_into().map_err(OracleProviderError::SliceConversion)
}
