//! Contains a concrete implementation of the [KeyValueStore] trait that stores data on disk,
//! using the [SingleChainHostCli] config.

use crate::host::single::cli::SingleChainHostCli;
use crate::host::single::orchestrator::DerivationRequest;
use alloy_primitives::B256;
use anyhow::Result;
use kona_host::KeyValueStore;
use kona_preimage::PreimageKey;
use kona_proof::boot::{
    L1_HEAD_KEY, L2_CHAIN_ID_KEY, L2_CLAIM_BLOCK_NUMBER_KEY, L2_CLAIM_KEY, L2_OUTPUT_ROOT_KEY,
    L2_ROLLUP_CONFIG_KEY,
};

/// The default chain ID to use if none is provided.
const DEFAULT_CHAIN_ID: u64 = 0xbeefbabe;

/// A simple, synchronous key-value store that returns data from a [SingleChainHostCli] config.
#[derive(Debug)]
pub struct LocalKeyValueStore {
    cfg: DerivationRequest,
}

impl LocalKeyValueStore {
    /// Create a new [LocalKeyValueStore] with the given [SingleChainHostCli] config.
    pub const fn new(cfg: DerivationRequest) -> Self {
        Self { cfg }
    }
}

impl KeyValueStore for LocalKeyValueStore {
    fn get(&self, key: B256) -> Option<Vec<u8>> {
        let preimage_key = PreimageKey::try_from(*key).ok()?;
        match preimage_key.key_value() {
            L1_HEAD_KEY => Some(self.cfg.l1_head_hash.to_vec()),
            L2_OUTPUT_ROOT_KEY => Some(self.cfg.agreed_l2_output_root.to_vec()),
            L2_CLAIM_KEY => Some(self.cfg.l2_output_root.to_vec()),
            L2_CLAIM_BLOCK_NUMBER_KEY => Some(self.cfg.l2_block_number.to_be_bytes().to_vec()),
            L2_CHAIN_ID_KEY => Some(self.cfg.l2_chain_id.to_be_bytes().to_vec()),
            L2_ROLLUP_CONFIG_KEY => {
                let rollup_config = self.cfg.rollup_config.clone();
                let serialized = serde_json::to_vec(&rollup_config).ok()?;
                Some(serialized)
            }
            _ => None,
        }
    }

    fn set(&mut self, _: B256, _: Vec<u8>) -> Result<()> {
        unreachable!("LocalKeyValueStore is read-only")
    }
}
