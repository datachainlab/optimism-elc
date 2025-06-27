use crate::errors;
use crate::errors::Error;
use crate::oracle::{MemoryOracleClient, NopeHintWriter};
use alloc::sync::Arc;
use alloy_consensus::Header;
use alloy_primitives::{Sealed, B256};
use core::clone::Clone;
use core::fmt::Debug;
use kona_client::fpvm_evm::FpvmOpEvmFactory;
use kona_client::single::fetch_safe_head_hash;
use kona_derive::sources::EthereumDataSource;
use kona_driver::Driver;
use kona_executor::TrieDBProvider;
use kona_genesis::RollupConfig;
use kona_proof::sync::new_oracle_pipeline_cursor;
use kona_proof::{
    executor::KonaExecutor,
    l1::{OracleBlobProvider, OracleL1ChainProvider, OraclePipeline},
    l2::OracleL2ChainProvider,
    BootInfo,
};
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

    pub fn verify(
        &self,
        chain_id: u64,
        rollup_config: &RollupConfig,
        oracle: MemoryOracleClient,
    ) -> Result<(Header, u64), Error> {
        kona_proof::block_on(self.run(chain_id, rollup_config, oracle))
    }

    /// Run the derivation pipeline to verify the claimed L2 output root.
    /// This is almost the same as kona-client.
    async fn run(
        &self,
        chain_id: u64,
        rollup_config: &RollupConfig,
        oracle: MemoryOracleClient,
    ) -> Result<(Header, u64), Error> {
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
        let oracle_for_preimage = oracle.clone();
        let oracle = Arc::new(oracle);
        let mut l1_provider = OracleL1ChainProvider::new(boot.l1_head, oracle.clone());
        let mut l2_provider =
            OracleL2ChainProvider::new(safe_head_hash, rollup_config.clone(), oracle.clone());
        let beacon = OracleBlobProvider::new(oracle.clone());

        let safe_head = l2_provider
            .header_by_hash(safe_head_hash)
            .map(|header| Sealed::new_unchecked(header, safe_head_hash))?;

        let cursor = new_oracle_pipeline_cursor(
            rollup_config.as_ref(),
            safe_head,
            &mut l1_provider,
            &mut l2_provider,
        )
        .await?;
        l2_provider.set_cursor(cursor.clone());

        let da_provider =
            EthereumDataSource::new_from_parts(l1_provider.clone(), beacon, &rollup_config);
        let pipeline = OraclePipeline::new(
            rollup_config.clone(),
            cursor.clone(),
            oracle.clone(),
            da_provider,
            l1_provider.clone(),
            l2_provider.clone(),
        )
        .await?;

        let evm_factory = FpvmOpEvmFactory::new(NopeHintWriter, oracle_for_preimage);
        let executor = KonaExecutor::new(
            rollup_config.as_ref(),
            l2_provider.clone(),
            l2_provider,
            evm_factory,
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
            return Err(errors::Error::InvalidClaim(
                output_root,
                boot.claimed_l2_output_root,
            ));
        }

        let read = driver.cursor.read();
        let l1_origin_number = read.l2_safe_head().l1_origin.number;
        let header = read.l2_safe_head_header().clone().unseal();
        Ok((header, l1_origin_number))
    }
}
