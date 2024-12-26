use crate::driver::DerivationDriver;
use crate::fault::fpvm_handle_register;
use alloc::format;
use alloc::sync::Arc;
use alloc::vec::Vec;
use alloy_consensus::{BlockHeader, Header};
use alloy_primitives::private::alloy_rlp::Decodable;
use alloy_primitives::{Sealable, B256};
use anyhow::{anyhow, Context, Error, Result};
use core::fmt::Debug;
use kona_client::l1::{OracleBlobProvider, OracleL1ChainProvider};
use kona_client::l2::OracleL2ChainProvider;
use kona_client::BootInfo;
use kona_preimage::{CommsClient, PreimageKey, PreimageKeyType};
use op_alloy_genesis::RollupConfig;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize)]
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
    pub async fn verify<T: CommsClient + Send + Sync + Debug>(
        &self,
        chain_id: u64,
        rollup_config: &RollupConfig,
        oracle: T,
    ) -> Result<Header> {
        let boot = Arc::new(BootInfo {
            l1_head: self.l1_head_hash,
            agreed_l2_output_root: self.agreed_l2_output_root,
            claimed_l2_output_root: self.l2_output_root,
            claimed_l2_block_number: self.l2_block_number,
            chain_id,
            rollup_config: rollup_config.clone(),
        });

        let oracle = Arc::new(oracle);
        let l1_provider = OracleL1ChainProvider::new(boot.clone(), oracle.clone());
        let l2_provider = OracleL2ChainProvider::new(boot.clone(), oracle.clone());
        let beacon = OracleBlobProvider::new(oracle.clone());

        let mut driver = DerivationDriver::new(
            &boot,
            self.agreed_l2_head_hash,
            oracle.as_ref(),
            beacon,
            l1_provider,
            l2_provider.clone(),
        )
        .await?;

        let (header, output_root) = driver
            .produce_output(
                &boot.rollup_config,
                &l2_provider,
                &l2_provider,
                fpvm_handle_register,
            )
            .await?;

        if header.number != boot.claimed_l2_block_number {
            return Err(Error::msg(format!(
                "Derivation failed by number expected={}, actual={}",
                boot.claimed_l2_block_number, header.number
            )));
        }
        if output_root != boot.claimed_l2_output_root {
            return Err(Error::msg(format!(
                "Derivation failed by root expected={}, actual={}",
                boot.claimed_l2_output_root, output_root
            )));
        }

        Ok(header)
    }
}

#[derive(Clone, Debug)]
pub struct Derivations {
    inner: Vec<Derivation>,
}

impl Derivations {
    pub fn new(inner: Vec<Derivation>) -> Self {
        Derivations { inner }
    }

    pub fn verify<T: CommsClient + Send + Sync + Debug>(
        &self,
        chain_id: u64,
        rollup_config: &RollupConfig,
        oracle: T,
    ) -> Result<Vec<(Header, B256)>> {
        let headers: Result<Vec<(Header, B256)>, Error> = kona_common::block_on(async move {
            let mut headers = Vec::with_capacity(self.inner.len());
            for (i, d) in self.inner.iter().enumerate() {
                let header = d
                    .verify(chain_id, rollup_config, oracle.clone())
                    .await
                    .context(format!(
                        "Derivation failed by index={}, number={}",
                        i, d.l2_block_number
                    ))?;

                // Verify collect order
                if i > 0 {
                    let prev_hash = self.inner[i - 1].l2_head_hash;
                    if header.parent_hash != prev_hash {
                        return Err(Error::msg(format!(
                            "Derivation failed by parent_hash expected={}, actual={}, block={}, index={}",
                            prev_hash,
                            header.parent_hash,
                            d.l2_block_number,
                            i
                        )));
                    }
                }

                headers.push((header, d.l2_output_root));
            }
            Ok(headers)
        });
        headers
    }

    pub fn last(&self) -> Option<&Derivation> {
        self.inner.last()
    }

    pub fn first(&self) -> Option<&Derivation> {
        self.inner.first()
    }
}
