use crate::errors::Error;
use crate::l1::L1Header;
use crate::oracle::MemoryOracleClient;
use alloc::vec::Vec;
use alloy_primitives::B256;
use ethereum_ibc::types::AccountUpdateInfo;
use light_client::types::{Any, Height};
use maili_genesis::RollupConfig;
use optimism_derivation::derivation::Derivation;
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
pub struct Header<const L1_SYNC_COMMITTEE_SIZE: usize> {
    trusted_height: Height,
    l1_headers: Vec<L1Header<L1_SYNC_COMMITTEE_SIZE>>,
    derivation: Derivation,
    account_update: AccountUpdateInfo,
    oracle: MemoryOracleClient,
    preimage_size: u64
}

impl<const L1_SYNC_COMMITTEE_SIZE: usize> Header<L1_SYNC_COMMITTEE_SIZE> {
    pub fn verify(
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
        let header = self.derivation
            .verify(chain_id, rollup_config, self.oracle.clone())
            .map_err(|e| Error::DerivationError(self.preimage_size, e))?;
        Ok((header, self.derivation.l2_output_root))
    }

    pub fn l1_headers(&self) -> &[L1Header<L1_SYNC_COMMITTEE_SIZE>] {
        &self.l1_headers
    }

    pub fn trusted_height(&self) -> Height {
        self.trusted_height
    }

    pub fn account_update(&self) -> &AccountUpdateInfo {
        &self.account_update
    }
}

impl<const L1_SYNC_COMMITTEE_SIZE: usize> TryFrom<RawHeader> for Header<L1_SYNC_COMMITTEE_SIZE> {
    type Error = Error;

    fn try_from(header: RawHeader) -> Result<Self, Self::Error> {
        let mut l1_headers: Vec<L1Header<L1_SYNC_COMMITTEE_SIZE>> = Vec::with_capacity(header.l1_headers.len());
        for l1_header in header.l1_headers {
            l1_headers.push(l1_header.try_into()?);
        }

        let l1_head_hash = B256::from(&l1_headers.last().as_ref().ok_or(Error::MissingL1Head)?
            .execution_update.block_hash.0);
        let raw_derivation = header.derivation.ok_or(Error::UnexpectedEmptyDerivations)?;
        let derivation = Derivation::new(
            l1_head_hash,
            B256::try_from(raw_derivation.agreed_l2_output_root.as_slice())
                .map_err(Error::UnexpectedAgreedL2HeadHash)?,
            B256::try_from(raw_derivation.l2_output_root.as_slice())
                .map_err(Error::UnexpectedL2OutputRoot)?,
            raw_derivation.l2_block_number
        );

        let preimage_size = header.preimages.len();
        let preimages = Preimages::decode(header.preimages.as_slice()).map_err(Error::ProtoDecodeError)?;
        let account_update_info = header
            .account_update
            .ok_or(Error::MissingAccountUpdate)?
            .try_into()
            .map_err(Error::L1IBCError)?;

        let oracle: MemoryOracleClient = preimages.preimages.try_into()?;
        let trusted_height = header.trusted_height.ok_or(Error::MissingTrustedHeight)?;
        Ok(Self {
            preimage_size: preimage_size as u64,
            l1_headers,
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
