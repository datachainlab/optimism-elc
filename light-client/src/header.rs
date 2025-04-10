use crate::consensus_state::ConsensusState;
use crate::errors::Error;
use crate::l1::{L1Config, L1Consensus, L1Header};
use alloc::boxed::Box;
use alloc::vec::Vec;
use alloy_primitives::B256;
use ethereum_ibc::types::AccountUpdateInfo;
use light_client::types::{Any, Height};
use maili_genesis::RollupConfig;
use optimism_derivation::derivation::Derivation;
use optimism_derivation::oracle::MemoryOracleClient;
use optimism_derivation::types::Preimages;
use optimism_ibc_proto::google::protobuf::Any as IBCAny;
use optimism_ibc_proto::ibc::lightclients::optimism::v1::Header as RawHeader;
use prost::Message;

pub const OPTIMISM_HEADER_TYPE_URL: &str = "/ibc.lightclients.optimism.v1.Header";

pub struct VerifyResult {
    pub l2_header: alloy_consensus::Header,
    pub l2_output_root: B256,
}

#[derive(Clone, Debug)]
pub struct L1Headers<const L1_SYNC_COMMITTEE_SIZE: usize> {
    trusted_to_definitive: Vec<L1Header<L1_SYNC_COMMITTEE_SIZE>>,
    definitive_to_latest: Vec<L1Header<L1_SYNC_COMMITTEE_SIZE>>,
}

impl<const L1_SYNC_COMMITTEE_SIZE: usize> L1Headers<L1_SYNC_COMMITTEE_SIZE> {
    pub fn verify(
        &self,
        l1_config: &L1Config,
        now_sec: u64,
        trusted_consensus_state: &ConsensusState,
    ) -> Result<L1Consensus, Error> {
        let mut l1_consensus = L1Consensus {
            slot: trusted_consensus_state.l1_slot,
            current_sync_committee: trusted_consensus_state.l1_current_sync_committee.clone(),
            next_sync_committee: trusted_consensus_state.l1_next_sync_committee.clone(),
        };

        let root = l1_consensus.clone();
        let mut updated_as_next = false;
        for (i, l1_header) in self.trusted_to_definitive.iter().enumerate() {
            let result = l1_header.verify(now_sec, l1_config, &l1_consensus);
            let result = result.map_err(|e| {
                Error::L1HeaderVerifyError(
                    i,
                    updated_as_next,
                    root.clone(),
                    l1_consensus,
                    Box::new(e),
                )
            })?;
            updated_as_next = result.0;
            l1_consensus = result.1;
        }

        // Verify finalized l1 header by last l1 consensus for L2 derivation
        let mut l1_consensus_for_verify_only = l1_consensus.clone();
        for (i, l1_header) in self.definitive_to_latest.iter().enumerate() {
            let result = l1_header.verify(now_sec, l1_config, &l1_consensus_for_verify_only);
            let result = result.map_err(|e| {
                Error::L1HeaderForDerivationVerifyError(
                    i,
                    updated_as_next,
                    root.clone(),
                    l1_consensus_for_verify_only,
                    Box::new(e),
                )
            })?;
            updated_as_next = result.0;
            l1_consensus_for_verify_only = result.1;
        }

        Ok(l1_consensus)
    }
}

#[derive(Clone, Debug)]
pub struct Header<const L1_SYNC_COMMITTEE_SIZE: usize> {
    pub trusted_height: Height,
    pub account_update: AccountUpdateInfo,
    l1_headers: L1Headers<L1_SYNC_COMMITTEE_SIZE>,
    derivation: Derivation,
    oracle: MemoryOracleClient,
}

impl<const L1_SYNC_COMMITTEE_SIZE: usize> Header<L1_SYNC_COMMITTEE_SIZE> {
    pub fn verify_l1(
        &self,
        l1_config: &L1Config,
        now_sec: u64,
        trusted_consensus_state: &ConsensusState,
    ) -> Result<L1Consensus, Error> {
        self.l1_headers
            .verify(l1_config, now_sec, trusted_consensus_state)
    }

    pub fn verify_l2(
        &self,
        chain_id: u64,
        trusted_output_root: B256,
        rollup_config: &RollupConfig,
    ) -> Result<(alloy_consensus::Header, B256), Error> {
        // Ensure trusted
        if self.derivation.agreed_l2_output_root != trusted_output_root {
            return Err(Error::UnexpectedTrustedOutputRoot(
                self.derivation.agreed_l2_output_root,
                trusted_output_root,
            ));
        }

        // Ensure honest derivation
        let header = self
            .derivation
            .verify(chain_id, rollup_config, self.oracle.clone())
            .map_err(|e| Error::DerivationError(self.derivation.clone(), self.oracle.len(), e))?;
        Ok((header, self.derivation.l2_output_root))
    }
}

impl<const L1_SYNC_COMMITTEE_SIZE: usize> TryFrom<RawHeader> for Header<L1_SYNC_COMMITTEE_SIZE> {
    type Error = Error;

    fn try_from(header: RawHeader) -> Result<Self, Self::Error> {
        let mut trusted_to_definitive: Vec<L1Header<L1_SYNC_COMMITTEE_SIZE>> = Vec::with_capacity(header.trusted_to_definitive.len());
        for l1_header in header.trusted_to_definitive {
            trusted_to_definitive.push(l1_header.try_into()?);
        }
        let mut definitive_to_latest : Vec<L1Header<L1_SYNC_COMMITTEE_SIZE>> = Vec::with_capacity(header.definitive_to_latest.len());
        for l1_header in header.definitive_to_latest {
            definitive_to_latest.push(l1_header.try_into()?);
        }
        let raw_derivation = header.derivation.ok_or(Error::UnexpectedEmptyDerivations)?;

        let derivation = Derivation::new(
            B256::from(definitive_to_latest.last().ok_or(Error::MissingL1Head)?.execution_update.block_hash.0),
            B256::try_from(raw_derivation.agreed_l2_output_root.as_slice())
                .map_err(Error::UnexpectedAgreedL2HeadHash)?,
            B256::try_from(raw_derivation.l2_output_root.as_slice())
                .map_err(Error::UnexpectedL2OutputRoot)?,
            raw_derivation.l2_block_number,
        );

        let preimages =
            Preimages::decode(header.preimages.as_slice()).map_err(Error::ProtoDecodeError)?;
        let account_update_info = header
            .account_update
            .ok_or(Error::MissingAccountUpdate)?
            .try_into()
            .map_err(Error::L1IBCError)?;

        let oracle: MemoryOracleClient = preimages
            .preimages
            .try_into()
            .map_err(Error::OracleClientError)?;
        let trusted_height = header.trusted_height.ok_or(Error::MissingTrustedHeight)?;
        Ok(Self {
            l1_headers: L1Headers {
                trusted_to_definitive,
                definitive_to_latest
            },
            trusted_height: Height::new(
                trusted_height.revision_number,
                trusted_height.revision_height,
            ),
            account_update: account_update_info,
            derivation,
            oracle,
        })
    }
}

impl<const L1_SYNC_COMMITTEE_SIZE: usize> TryFrom<IBCAny> for Header<L1_SYNC_COMMITTEE_SIZE> {
    type Error = Error;

    fn try_from(any: IBCAny) -> Result<Header<L1_SYNC_COMMITTEE_SIZE>, Self::Error> {
        if any.type_url != OPTIMISM_HEADER_TYPE_URL {
            return Err(Error::UnknownHeaderType(any.type_url));
        }
        let raw = RawHeader::decode(any.value.as_slice()).map_err(Error::ProtoDecodeError)?;
        raw.try_into()
    }
}

impl<const L1_SYNC_COMMITTEE_SIZE: usize> TryFrom<Any> for Header<L1_SYNC_COMMITTEE_SIZE> {
    type Error = Error;

    fn try_from(any: Any) -> Result<Self, Self::Error> {
        IBCAny::from(any).try_into()
    }
}
