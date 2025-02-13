use crate::client::precompiles::fpvm_handle_register;
use alloc::sync::Arc;
use alloy_consensus::Header;
use alloy_primitives::{Sealed, B256};
use anyhow::Result;
use core::fmt::Debug;
use kona_client::single::{fetch_safe_head_hash, FaultProofProgramError};
use kona_driver::Driver;
use kona_executor::TrieDBProvider;
use kona_preimage::CommsClient;
use kona_proof::{
    executor::KonaExecutor,
    l1::{OracleBlobProvider, OracleL1ChainProvider, OraclePipeline},
    l2::OracleL2ChainProvider,
    sync::new_pipeline_cursor,
    BootInfo, FlushableCache,
};
use maili_genesis::RollupConfig;
use serde::{Deserialize, Serialize};
use tracing::{error, info};

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
        let safe_head_hash = fetch_safe_head_hash(&oracle, boot).await?;
        let oracle = Arc::new(oracle);
        let mut l1_provider = OracleL1ChainProvider::new(boot.l1_head, oracle.clone());
        let mut l2_provider =
            OracleL2ChainProvider::new(safe_head_hash, boot.rollup_config.clone(), oracle.clone());
        let beacon = OracleBlobProvider::new(oracle.clone());

        let safe_head = l2_provider
            .header_by_hash(safe_head_hash)
            .map(|header| Sealed::new_unchecked(header, safe_head_hash))?;

        let cursor = new_pipeline_cursor(
            &boot.rollup_config,
            safe_head,
            &mut l1_provider,
            &mut l2_provider,
        )
        .await?;
        l2_provider.set_cursor(cursor.clone());

        let cfg = Arc::new(boot.rollup_config.clone());
        let pipeline = OraclePipeline::new(
            cfg.clone(),
            cursor.clone(),
            oracle.clone(),
            beacon,
            l1_provider.clone(),
            l2_provider.clone(),
        );
        let executor = KonaExecutor::new(
            &cfg,
            l2_provider.clone(),
            l2_provider,
            Some(fpvm_handle_register),
            None,
        );
        let mut driver = Driver::new(cursor, executor, pipeline);

        // Run the derivation pipeline until we are able to produce the output root of the claimed
        // L2 block.
        let (number, _, output_root) = driver
            .advance_to_target(&boot.rollup_config, Some(boot.claimed_l2_block_number))
            .await?;

        ////////////////////////////////////////////////////////////////
        //                          EPILOGUE                          //
        ////////////////////////////////////////////////////////////////

        if output_root != boot.claimed_l2_output_root {
            error!(
                target: "client",
                "Failed to validate L2 block #{number} with output root {output_root}",
                number = number,
                output_root = output_root
            );
            return Err(FaultProofProgramError::InvalidClaim(
                output_root,
                boot.claimed_l2_output_root,
            )
            .into());
        }

        info!(
            target: "client",
            "Successfully validated L2 block #{number} with output root {output_root}",
            number = number,
            output_root = output_root
        );
        let read = driver.cursor.read();
        let header = read.l2_safe_head_header().clone().unseal();
        Ok(header)
    }
}
