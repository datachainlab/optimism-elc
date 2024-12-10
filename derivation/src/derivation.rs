use crate::driver::DerivationDriver;
use crate::fault::fpvm_handle_register;
use alloc::format;
use alloc::sync::Arc;
use alloc::vec::Vec;
use alloy_consensus::{BlockHeader, Header};
use alloy_primitives::{Sealable, B256};
use anyhow::{anyhow, Context, Error, Result};
use core::fmt::Debug;
use alloy_primitives::private::alloy_rlp::Decodable;
use kona_client::l1::{OracleBlobProvider, OracleL1ChainProvider};
use kona_client::l2::OracleL2ChainProvider;
use kona_client::BootInfo;
use kona_preimage::{CommsClient, PreimageKey, PreimageKeyType};
use op_alloy_genesis::RollupConfig;
use serde::Deserialize;

#[derive(Clone, Debug, Deserialize)]
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
        oracle: Arc<T>,
    ) -> Result<Header> {
        let boot = Arc::new(BootInfo {
            l1_head: self.l1_head_hash,
            agreed_l2_output_root: self.agreed_l2_output_root,
            claimed_l2_output_root: self.l2_output_root,
            claimed_l2_block_number: self.l2_block_number,
            chain_id,
            rollup_config: rollup_config.clone(),
        });

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
        oracle: Arc<T>,
    ) -> Result<Vec<(Header, B256)>> {
        let headers: Result<Vec<(Header, B256)>, Error> = kona_common::block_on(async move {
            let mut headers = Vec::with_capacity(self.inner.len());
            for (i, d) in self.inner.iter().enumerate() {
                if i > 0 {
                    // Ensure collect order
                    let parent_hash = self.inner.get(i - 1).unwrap().l2_head_hash;

                    let l2_head = oracle.get(PreimageKey::new(d.l2_head_hash.0, PreimageKeyType::Keccak256)).await?;
                    let l2_head = Header::decode(&mut l2_head.as_slice())
                        .map_err(|e| anyhow!(e))?;

                    if l2_head.parent_hash != parent_hash {
                        return Err(Error::msg(format!(
                            "Derivation failed by parent hash expected={}, actual={}",
                            parent_hash, l2_head.parent_hash
                        )));
                    }
                }

                let header = d.verify(chain_id, rollup_config, oracle.clone()).await?;
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
