use alloc::sync::Arc;
use crate::errors::Error;
use crate::l1::{L1Config, L1Header, L1Verifier};
use crate::oracle::MemoryOracleClient;
use alloc::vec::Vec;
use alloy_primitives::B256;
use ethereum_ibc::types::AccountUpdateInfo;
use hashbrown::HashSet;
use light_client::types::{Height, Time};
use op_alloy_genesis::RollupConfig;
use optimism_derivation::derivation::{Derivation, Derivations};
use optimism_ibc_proto::ibc::lightclients::optimism::v1::Header as RawHeader;

pub struct VerifyResult {
    pub l2_header: alloy_consensus::Header,
    pub l2_output_root: B256,
}

pub struct Header<const L1_SYNC_COMMITTEE_SIZE: usize> {
    trusted_height: Height,
    derivations: Derivations,
    oracle: Arc<MemoryOracleClient>,
    account_update: AccountUpdateInfo,
    l1_headers: Vec<L1Header<L1_SYNC_COMMITTEE_SIZE>>,
}

impl<const L1_SYNC_COMMITTEE_SIZE: usize> Header<L1_SYNC_COMMITTEE_SIZE> {
    pub fn verify(
        &self,
        chain_id: u64,
        rollup_config: &RollupConfig,
    ) -> Result<VerifyResult, Self::Error> {
        let headers = self
            .derivations
            .verify(chain_id, rollup_config, self.oracle.clone())?;
        let (header, output_root) = headers.last().ok_or(Error::UnexpectedEmptyDerivations)?;
        Ok(VerifyResult {
            l2_header: header.clone(),
            l2_output_root: output_root.clone(),
        })
    }

    pub fn verify_l1(&self, now: Time, l1_config: &L1Config) -> Result<(), Error> {
        let now = now.as_unix_timestamp_secs();
        let l1_verifier = L1Verifier::<L1_SYNC_COMMITTEE_SIZE>::new();
        for l1_header in self.l1_headers.iter() {
            l1_verifier.verify(now, &l1_config, l1_header)?;
        }
        Ok(())
    }

    pub fn trusted_height(&self) -> Height {
        self.trusted_height
    }

    pub fn account_update_ref(&self) -> &AccountUpdateInfo {
        &self.account_update
    }
}

impl<const L1_SYNC_COMMITTEE_SIZE: usize> TryFrom<RawHeader> for Header<L1_SYNC_COMMITTEE_SIZE> {
    type Error = Error;

    fn try_from(header: RawHeader) -> Result<Self, Self::Error> {
        if header.derivations.is_empty() {
            return Err(Error::UnexpectedEmptyDerivations);
        }

        let mut l1_headers = Vec::with_capacity(header.derivations.len());
        let mut l1_header_nums = HashSet::new();

        //TODO Test if sorted
        let mut derivations = Vec::with_capacity(header.derivations.len());
        for derivation in header.derivations {
            let l1_head = derivation.l1_head.ok_or(Error::MissingL1Head)?;
            let l1_consensus_update = l1_head
                .consensus_update
                .as_ref()
                .ok_or(Error::MissingL1ConsensusUpdate)?;
            let l1_head_hash: B256 = l1_consensus_update
                .finalized_execution_root
                .clone()
                .try_into()?;

            if l1_header_nums.insert(l1_head_hash) {
                l1_headers.push(l1_head.try_into()?);
            }
            derivations.push(Derivation::new(
                l1_head_hash,
                B256::try_from(derivation.agreed_l2_head_hash)?,
                B256::try_from(derivation.agreed_l2_output_root)?,
                B256::try_from(derivation.l2_head_hash)?,
                B256::try_from(derivation.l2_output_root)?,
                derivation.l2_block_number,
            ));
        }
        let derivations = Derivations::new(derivations);
        let oracle: MemoryOracleClient = header.preimages.try_into()?;
        let account_update = header.account_update.unwrap().try_into()?;
        Ok(Self {
            l1_headers,
            trusted_height,
            account_update,
            derivations,
            oracle: Arc::new(oracle),
        })
    }
}
