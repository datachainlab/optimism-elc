use crate::fault::fpvm_handle_register;
use alloc::format;
use alloc::sync::Arc;
use alloc::vec::Vec;
use alloy_primitives::B256;
use anyhow::{Error, Result};
use kona_client::l1::{DerivationDriver, OracleBlobProvider, OracleL1ChainProvider};
use kona_client::l2::OracleL2ChainProvider;
use kona_client::BootInfo;
use kona_preimage::CommsClient;
use op_alloy_genesis::RollupConfig;

pub struct Derivation {
    pub l1_head_hash: B256,
    pub agreed_l2_head_hash: B256,
    pub agreed_l2_output_root: B256,
    pub l2_head_hash: B256,
    pub l2_output_root: B256,
    pub l2_block_number: u64,
}

impl Derivation {
    pub fn new(
        l1_head_hash: B256,
        agreed_l2_head_hash: B256,
        agreed_l2_output_root: B256,
        l2_head_hash: B256,
        l2_output_root: B256,
        l2_block_number: u64,
    ) -> Self {
        Derivation {
            l1_head_hash,
            agreed_l2_head_hash,
            agreed_l2_output_root,
            l2_head_hash,
            l2_output_root,
            l2_block_number,
        }
    }
    pub async fn verify(
        &self,
        chain_id: u64,
        rollup_config: RollupConfig,
        oracle: impl CommsClient,
    ) -> Result<()> {
        let boot = Arc::new(BootInfo {
            l1_head: self.l1_head_hash,
            agreed_l2_output_root: self.agreed_l2_output_root,
            claimed_l2_output_root: self.l2_output_root,
            claimed_l2_block_number: self.l2_block_number,
            chain_id: chain_id.clone(),
            rollup_config: rollup_config.clone(),
        });

        let l1_provider = OracleL1ChainProvider::new(boot.clone(), oracle.clone());
        let l2_provider = OracleL2ChainProvider::new(boot.clone(), oracle.clone());
        let beacon = OracleBlobProvider::new(oracle.clone());

        let mut driver = DerivationDriver::new(
            &boot,
            oracle.as_ref(),
            beacon,
            l1_provider,
            l2_provider.clone(),
        )
        .await?;

        let (number, output_root) = driver
            .produce_output(
                &boot.rollup_config,
                &l2_provider,
                &l2_provider,
                fpvm_handle_register,
            )
            .await?;

        if number != boot.claimed_l2_block_number {
            return Err(Error::msg(format!(
                "Derivation failed by number expected={}, actual={}",
                boot.claimed_l2_block_number, number
            )));
        }
        if output_root != boot.claimed_l2_output_root {
            return Err(Error::msg(format!(
                "Derivation failed by root expected={}, actual={}",
                boot.claimed_l2_output_root, output_root
            )));
        }

        Ok(())
    }
}

pub struct Derivations {
    inner: Vec<Derivation>,
}

impl Derivations {
    pub fn new() -> Self {
        Derivations { inner: Vec::new() }
    }
    pub async fn verify(
        &self,
        chain_id: u64,
        rollup_config: RollupConfig,
        oracle: impl CommsClient,
    ) -> Result<()> {
        for d in &self.inner {
            d.verify(chain_id, rollup_config, oracle).await?;
        }
        Ok(())
    }
}
