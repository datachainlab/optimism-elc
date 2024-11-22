use alloc::sync::Arc;
use crate::errors::Error;
use crate::l1::{L1Config, L1Header, L1Verifier};
use crate::oracle::MemoryOracleClient;
use alloc::vec::Vec;
use alloy_primitives::{B256};
use ethereum_ibc::types::AccountUpdateInfo;
use hashbrown::HashSet;
use light_client::types::{Any, Height, Time};
use op_alloy_genesis::RollupConfig;
use prost::Message;
use optimism_derivation::derivation::{Derivation, Derivations};
use optimism_ibc_proto::ibc::lightclients::optimism::v1::Header as RawHeader;
use optimism_ibc_proto::google::protobuf::Any as IBCAny;

pub const OPTIMISM_HEADER_TYPE_URL: &str = "/ibc.lightclients.optimism.v1.Header";

pub struct VerifyResult {
    pub l2_header: alloy_consensus::Header,
    pub l2_output_root: B256,
}

#[derive(Clone, Debug)]
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
        let l1_verifier = L1Verifier::<L1_SYNC_COMMITTEE_SIZE>::default();
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

            let l1_head_hash = B256::try_from(l1_consensus_update
                .finalized_execution_root.as_slice()).map_err(Error::UnexpectedL1HeadHash)?;

            if l1_header_nums.insert(l1_head_hash) {
                l1_headers.push(l1_head.try_into()?);
            }
            derivations.push(Derivation::new(
                l1_head_hash,
                B256::try_from(derivation.agreed_l2_head_hash.as_slice()).map_err(Error::UnexpectedAgreedL2HeadHash)?,
                B256::try_from(derivation.agreed_l2_output_root.as_slice()).map_err(Error::UnexpectedAgreedL2OutputRoot)?,
                B256::try_from(derivation.l2_head_hash.as_slice()).map_err(Error::UnexpectedL2HeadHash)?,
                B256::try_from(derivation.l2_output_root.as_slice()).map_err(Error::UnexpectedL2OutputRoot)?,
                derivation.l2_block_number,
            ));
        }
        let derivations = Derivations::new(derivations);
        let oracle: MemoryOracleClient = header.preimages.try_into()?;
        let account_update = header.account_update
            .ok_or(Error::MissingAccountUpdate)?.try_into().map_err(Error::L1IBCError)?;
        Ok(Self {
            l1_headers,
            trusted_height,
            account_update,
            derivations,
            oracle: Arc::new(oracle),
        })
    }
}

impl<const L1_SYNC_COMMITTEE_SIZE:usize> TryFrom<IBCAny> for Header<L1_SYNC_COMMITTEE_SIZE> {
    type Error = Error;

    fn try_from(any: IBCAny) -> Result<Header<L1_SYNC_COMMITTEE_SIZE>, Self::Error> {
        if any.type_url != OPTIMISM_HEADER_TYPE_URL {
            return Err(Error::UnknownHeaderType(any.type_url));
        }
        let raw = RawHeader::decode(any.value.as_slice()).map_err(Error::ProtoDecodeError)?;
        raw.try_into()
    }
}

impl<const L1_SYNC_COMMITTEE_SIZE:usize> TryFrom<Any> for Header<L1_SYNC_COMMITTEE_SIZE> {
    type Error = Error;

    fn try_from(any: Any) -> Result<Self, Self::Error> {
        IBCAny::from(any).try_into()
    }
}