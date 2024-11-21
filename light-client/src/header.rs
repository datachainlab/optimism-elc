use crate::errors::Error;
use crate::oracle::MemoryOracleClient;
use crate::types::ChainId;
use alloc::vec::Vec;
use alloy_primitives::B256;
use ethereum_ibc::types::AccountUpdateInfo;
use light_client::types::Height;
use op_alloy_genesis::RollupConfig;
use optimism_derivation::derivation::{Derivation, Derivations};
use optimism_ibc_proto::ibc::lightclients::optimism::v1::Header as RawHeader;

pub struct VerifyResult {
    pub l2_header: alloy_consensus::Header,
    pub l2_output_root: B256,
}

pub struct Header {
    trusted_height: Height,
    derivations: Derivations,
    oracle: MemoryOracleClient,
    account_update: AccountUpdateInfo,
}

impl Header {
    pub fn verify(
        &self,
        chain_id: &ChainId,
        rollup_config: &RollupConfig,
    ) -> Result<VerifyResult, Self::Error> {
        let headers = self
            .derivations
            .verify(chain_id.id(), rollup_config, &self.oracle)?;
        let (header, output_root) = headers.last().ok_or(Error::UnexpectedEmptyDerivations)?;
        Ok(VerifyResult {
            l2_header: header.clone(),
            l2_output_root: output_root.clone(),
        })
    }

    pub fn trusted_height(&self) -> Height {
        self.trusted_height
    }

    pub fn account_update_ref(&self) -> &AccountUpdateInfo {
        &self.account_update
    }
}

impl TryFrom<RawHeader> for Header {
    type Error = Error;

    fn try_from(header: RawHeader) -> Result<Self, Self::Error> {
        if header.derivations.is_empty() {
            return Err(Error::UnexpectedEmptyDerivations);
        }

        //TODO Test if sorted
        let mut derivations = Vec::with_capacity(header.derivations.len());
        for derivation in header.derivations {
            let l1_head = derivation
                .l1_head
                .unwrap()
                .consensus_update
                .unwrap()
                .finalized_execution_root;
            derivations.push(Derivation::new(
                B256::try_from(l1_head),
                B256::try_from(derivation.agreed_l2_head_hash),
                B256::try_from(derivation.agreed_l2_output_root),
                B256::try_from(derivation.l1_head),
                B256::try_from(derivation.l2_output_root),
                derivation.l2_block_number,
            ));
        }
        let derivations = Derivations::new(derivations);
        let oracle: MemoryOracleClient = header.preimages.try_into()?;
        let account_update = header.account_update.unwrap().try_into()?;
        Ok(Self {
            trusted_height,
            account_update,
            derivations,
            oracle,
        })
    }
}
