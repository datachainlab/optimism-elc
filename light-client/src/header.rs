use crate::account::AccountUpdateInfo;
use crate::consensus_state::ConsensusState;
use crate::errors::Error;
use crate::l1::{L1Config, L1Consensus, L1Header};
use alloc::boxed::Box;
use alloc::vec::Vec;
use alloy_primitives::B256;
use light_client::types::{Any, Height};
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
    /// L1 headers from trusted to deterministic
    /// The final element in this list must be an L1 header that can be derived deterministically from the L2 header.
    /// And it must be stored in ConsensusState.
    trusted_to_deterministic: Vec<L1Header<L1_SYNC_COMMITTEE_SIZE>>,
    /// L1 headers from deterministic to latest
    /// While the header is already finalized in L1, the latest is not necessarily deterministic from the L2 header.
    ///
    /// Consider the case where the LATEST is stored in ConsensusState.
    /// The prover cannot retrieve information held in ConsensusState. Therefore, if the latest is stored in ConsensusState, the trusted state cannot be restored by prover and update_client cannot be executed.
    deterministic_to_latest: Vec<L1Header<L1_SYNC_COMMITTEE_SIZE>>,
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
            timestamp: trusted_consensus_state.l1_timestamp,
        };

        let mut updated_as_next = false;
        for (i, l1_header) in self.trusted_to_deterministic.iter().enumerate() {
            let result = l1_header.verify(now_sec, l1_config, &l1_consensus);
            let result = result.map_err(|e| {
                Error::L1HeaderTrustedToDeterministicVerifyError(
                    i,
                    updated_as_next,
                    l1_consensus,
                    Box::new(e),
                )
            })?;
            updated_as_next = result.0;
            l1_consensus = result.1;
        }

        // Verify finalized l1 header by last l1 consensus for L2 derivation
        let mut l1_consensus_for_verify_only = l1_consensus.clone();
        for (i, l1_header) in self.deterministic_to_latest.iter().enumerate() {
            let result = l1_header.verify(now_sec, l1_config, &l1_consensus_for_verify_only);
            let result = result.map_err(|e| {
                Error::L1HeaderDeterministicToLatestVerifyError(
                    i,
                    updated_as_next,
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
    ) -> Result<(alloy_consensus::Header, u64, B256), Error> {
        // Ensure trusted
        if self.derivation.agreed_l2_output_root != trusted_output_root {
            return Err(Error::UnexpectedTrustedOutputRoot(
                self.derivation.agreed_l2_output_root,
                trusted_output_root,
            ));
        }

        // Ensure honest derivation
        let result = self
            .derivation
            .verify(chain_id, self.oracle.clone())
            .map_err(|e| Error::DerivationError(self.derivation.clone(), self.oracle.len(), e))?;
        Ok((result.0, result.1, self.derivation.l2_output_root))
    }
}

impl<const L1_SYNC_COMMITTEE_SIZE: usize> TryFrom<RawHeader> for Header<L1_SYNC_COMMITTEE_SIZE> {
    type Error = Error;

    fn try_from(header: RawHeader) -> Result<Self, Self::Error> {
        let mut trusted_to_deterministic: Vec<L1Header<L1_SYNC_COMMITTEE_SIZE>> =
            Vec::with_capacity(header.trusted_to_deterministic.len());
        for l1_header in header.trusted_to_deterministic {
            trusted_to_deterministic.push(l1_header.try_into()?);
        }
        let mut deterministic_to_latest: Vec<L1Header<L1_SYNC_COMMITTEE_SIZE>> =
            Vec::with_capacity(header.deterministic_to_latest.len());
        for l1_header in header.deterministic_to_latest {
            deterministic_to_latest.push(l1_header.try_into()?);
        }
        let raw_derivation = header.derivation.ok_or(Error::UnexpectedEmptyDerivations)?;

        let derivation = Derivation::new(
            B256::from(
                deterministic_to_latest
                    .last()
                    .ok_or(Error::MissingL1Head)?
                    .execution_update
                    .block_hash
                    .0,
            ),
            B256::try_from(raw_derivation.agreed_l2_output_root.as_slice())
                .map_err(Error::UnexpectedAgreedL2HeadOutput)?,
            B256::try_from(raw_derivation.l2_output_root.as_slice())
                .map_err(Error::UnexpectedL2OutputRoot)?,
            raw_derivation.l2_block_number,
        );

        let preimages =
            Preimages::decode(header.preimages.as_slice()).map_err(Error::ProtoDecodeError)?;
        let account_update_info = header
            .account_update
            .ok_or(Error::MissingAccountUpdate)?
            .try_into()?;

        let oracle: MemoryOracleClient = preimages
            .preimages
            .try_into()
            .map_err(Error::OracleClientError)?;
        let trusted_height = header.trusted_height.ok_or(Error::MissingTrustedHeight)?;
        Ok(Self {
            l1_headers: L1Headers {
                trusted_to_deterministic,
                deterministic_to_latest,
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

#[cfg(test)]
mod test {
    use crate::consensus_state::ConsensusState;
    use crate::errors::Error;
    use crate::header::{Header, L1Headers};
    use crate::l1::tests::{
        get_l1_config, get_l1_consensus, get_l1_header, get_raw_l1_header, get_time,
    };
    use alloc::vec;
    use alloy_primitives::hex;

    use optimism_derivation::types::{Preimage, Preimages};
    use optimism_ibc_proto::ibc::lightclients::optimism::v1::AccountUpdate as RawAccountUpdate;
    use optimism_ibc_proto::ibc::lightclients::optimism::v1::Derivation as RawDerivation;
    use optimism_ibc_proto::ibc::lightclients::optimism::v1::Header as RawHeader;

    fn get_empty_raw_header() -> RawHeader {
        RawHeader::default()
    }

    #[test]
    fn test_try_from_error_empty_derivation() {
        let raw_header = get_empty_raw_header();
        let err = Header::<{ ethereum_consensus::preset::minimal::PRESET.SYNC_COMMITTEE_SIZE} >::try_from(raw_header).unwrap_err();
        match err {
            Error::UnexpectedEmptyDerivations => {}
            _ => panic!("Unexpected error: {:?}", err),
        }
    }

    #[test]
    fn test_try_from_error_missing_l1() {
        let mut raw_header = get_empty_raw_header();
        raw_header.derivation = Some(
            optimism_ibc_proto::ibc::lightclients::optimism::v1::Derivation {
                agreed_l2_output_root: vec![],
                l2_output_root: vec![],
                l2_block_number: 0,
            },
        );
        let err = Header::<{ ethereum_consensus::preset::minimal::PRESET.SYNC_COMMITTEE_SIZE} >::try_from(raw_header).unwrap_err();
        match err {
            Error::MissingL1Head => {}
            _ => panic!("Unexpected error: {:?}", err),
        }
    }

    #[test]
    fn test_try_from_error_empty_agreed_l2_output() {
        let mut raw_header = get_empty_raw_header();
        raw_header.deterministic_to_latest = vec![get_raw_l1_header()];
        raw_header.derivation = Some(
            optimism_ibc_proto::ibc::lightclients::optimism::v1::Derivation {
                agreed_l2_output_root: vec![],
                l2_output_root: vec![],
                l2_block_number: 0,
            },
        );
        let err = Header::<{ ethereum_consensus::preset::minimal::PRESET.SYNC_COMMITTEE_SIZE} >::try_from(raw_header).unwrap_err();
        match err {
            Error::UnexpectedAgreedL2HeadOutput(_) => {}
            _ => panic!("Unexpected error: {:?}", err),
        }
    }

    #[test]
    fn test_try_from_error_empty_l2_output() {
        let mut raw_header = get_empty_raw_header();
        raw_header.deterministic_to_latest = vec![get_raw_l1_header()];
        raw_header.derivation = Some(
            optimism_ibc_proto::ibc::lightclients::optimism::v1::Derivation {
                agreed_l2_output_root: [0u8; 32].into(),
                l2_output_root: vec![],
                l2_block_number: 0,
            },
        );
        let err = Header::<{ ethereum_consensus::preset::minimal::PRESET.SYNC_COMMITTEE_SIZE} >::try_from(raw_header).unwrap_err();
        match err {
            Error::UnexpectedL2OutputRoot(_) => {}
            _ => panic!("Unexpected error: {:?}", err),
        }
    }

    #[test]
    fn test_try_from_error_empty_account_update() {
        let mut raw_header = get_empty_raw_header();
        raw_header.deterministic_to_latest = vec![get_raw_l1_header()];
        raw_header.derivation = Some(
            optimism_ibc_proto::ibc::lightclients::optimism::v1::Derivation {
                agreed_l2_output_root: [0u8; 32].into(),
                l2_output_root: [0u8; 32].into(),
                l2_block_number: 0,
            },
        );
        let err = Header::<{ ethereum_consensus::preset::minimal::PRESET.SYNC_COMMITTEE_SIZE} >::try_from(raw_header).unwrap_err();
        match err {
            Error::MissingAccountUpdate => {}
            _ => panic!("Unexpected error: {:?}", err),
        }
    }

    #[test]
    fn test_try_from_error_empty_trusted_height() {
        let mut raw_header = get_empty_raw_header();
        raw_header.deterministic_to_latest = vec![get_raw_l1_header()];
        raw_header.derivation = Some(RawDerivation {
            agreed_l2_output_root: [0u8; 32].into(),
            l2_output_root: [0u8; 32].into(),
            l2_block_number: 0,
        });
        raw_header.account_update = Some(
            RawAccountUpdate {
                account_proof: hex!("f90159f901118080a0143145e818eeff83817419a6632ea193fd1acaa4f791eb17282f623f38117f56a0e6ee0a993a7254ee9253d766ea005aec74eb1e11656961f0fb11323f4f91075580808080a01efae04adc2e970b4af3517581f41ce2ba4ff60492d33696c1e2a5ab70cb55bba03bac3f5124774e41fb6efdd7219530846f9f6441045c4666d2855c6598cfca00a020d7122ffc86cb37228940b5a9441e9fd272a3450245c9130ca3ab00bc1cd6ef80a0047f255205a0f2b0e7d29d490abf02bfb62c3ed201c338bc7f0088fa9c5d77eda069fecc766fcb2df04eb3a834b1f4ba134df2be114479e251d9cc9b6ba493077b80a094c3ed6a7ef63a6a67e46cc9876b9b1882eeba3d28e6d61bb15cdfb207d077e180f843a03e077f3dfd0489e70c68282ced0126c62fcef50acdcb7f57aa4552b87b456b11a1a05dc044e92e82db28c96fd98edd502949612b06e8da6dd74664a43a5ed857b298").to_vec(),
                account_storage_root: [0u8;32].into(),
            }
        );
        let err = Header::<{ ethereum_consensus::preset::minimal::PRESET.SYNC_COMMITTEE_SIZE} >::try_from(raw_header).unwrap_err();
        match err {
            Error::MissingTrustedHeight => {}
            _ => panic!("Unexpected error: {:?}", err),
        }
    }

    #[test]
    fn test_try_from_error_invalid_oracle() {
        let mut raw_header = get_empty_raw_header();
        raw_header.deterministic_to_latest = vec![get_raw_l1_header()];
        raw_header.derivation = Some(RawDerivation {
            agreed_l2_output_root: [0u8; 32].into(),
            l2_output_root: [0u8; 32].into(),
            l2_block_number: 0,
        });
        raw_header.account_update = Some(
            RawAccountUpdate {
                account_proof: hex!("f90159f901118080a0143145e818eeff83817419a6632ea193fd1acaa4f791eb17282f623f38117f56a0e6ee0a993a7254ee9253d766ea005aec74eb1e11656961f0fb11323f4f91075580808080a01efae04adc2e970b4af3517581f41ce2ba4ff60492d33696c1e2a5ab70cb55bba03bac3f5124774e41fb6efdd7219530846f9f6441045c4666d2855c6598cfca00a020d7122ffc86cb37228940b5a9441e9fd272a3450245c9130ca3ab00bc1cd6ef80a0047f255205a0f2b0e7d29d490abf02bfb62c3ed201c338bc7f0088fa9c5d77eda069fecc766fcb2df04eb3a834b1f4ba134df2be114479e251d9cc9b6ba493077b80a094c3ed6a7ef63a6a67e46cc9876b9b1882eeba3d28e6d61bb15cdfb207d077e180f843a03e077f3dfd0489e70c68282ced0126c62fcef50acdcb7f57aa4552b87b456b11a1a05dc044e92e82db28c96fd98edd502949612b06e8da6dd74664a43a5ed857b298").to_vec(),
                account_storage_root: [0u8;32].into(),
            }
        );

        // proto error
        raw_header.preimages = [0u8; 1].into();
        let err = Header::<{ ethereum_consensus::preset::minimal::PRESET.SYNC_COMMITTEE_SIZE} >::try_from(raw_header.clone()).unwrap_err();
        match err {
            Error::ProtoDecodeError(_) => {}
            _ => panic!("Unexpected error: {:?}", err),
        }

        // invalid oracle
        let preimages = Preimages {
            preimages: vec![Preimage {
                key: vec![],
                data: vec![],
            }],
        }
        .into_vec()
        .unwrap();
        raw_header.preimages = preimages;
        let err = Header::<{ ethereum_consensus::preset::minimal::PRESET.SYNC_COMMITTEE_SIZE} >::try_from(raw_header).unwrap_err();
        match err {
            Error::OracleClientError(_) => {}
            _ => panic!("Unexpected error: {:?}", err),
        }
    }

    #[test]
    fn test_l1_headers_verify_trusted_to_deterministic_error() {
        let mut l1_headers = L1Headers {
            trusted_to_deterministic: vec![get_l1_header()],
            deterministic_to_latest: vec![get_l1_header()],
        };
        l1_headers.trusted_to_deterministic[0]
            .execution_update
            .block_hash_branch = vec![];

        let l1_cons_state = get_l1_consensus();
        let cons_state = ConsensusState {
            l1_slot: l1_cons_state.slot,
            l1_current_sync_committee: l1_cons_state.current_sync_committee,
            l1_next_sync_committee: l1_cons_state.next_sync_committee,
            ..Default::default()
        };
        let err = l1_headers
            .verify(&get_l1_config(), get_time(), &cons_state)
            .unwrap_err();
        match err {
            Error::L1HeaderTrustedToDeterministicVerifyError(_, _, _, _) => {}
            _ => panic!("Unexpected error: {:?}", err),
        }
    }

    #[test]
    fn test_l1_headers_verify_deterministic_to_latest_error() {
        let mut l1_headers = L1Headers {
            trusted_to_deterministic: vec![get_l1_header()],
            deterministic_to_latest: vec![get_l1_header()],
        };
        l1_headers.deterministic_to_latest[0]
            .execution_update
            .block_hash_branch = vec![];

        let l1_cons_state = get_l1_consensus();
        let cons_state = ConsensusState {
            l1_slot: l1_cons_state.slot,
            l1_current_sync_committee: l1_cons_state.current_sync_committee,
            l1_next_sync_committee: l1_cons_state.next_sync_committee,
            ..Default::default()
        };
        let err = l1_headers
            .verify(&get_l1_config(), get_time(), &cons_state)
            .unwrap_err();
        match err {
            Error::L1HeaderDeterministicToLatestVerifyError(_, _, _, _) => {}
            _ => panic!("Unexpected error: {:?}", err),
        }
    }

    #[test]
    fn test_l2_header_verify_unexpected_output_root() {
        let mut raw_header = get_empty_raw_header();
        raw_header.deterministic_to_latest = vec![get_raw_l1_header()];
        raw_header.derivation = Some(RawDerivation {
            agreed_l2_output_root: [0u8; 32].into(),
            l2_output_root: [0u8; 32].into(),
            l2_block_number: 2,
        });
        raw_header.account_update = Some(
            RawAccountUpdate {
                account_proof: hex!("f90159f901118080a0143145e818eeff83817419a6632ea193fd1acaa4f791eb17282f623f38117f56a0e6ee0a993a7254ee9253d766ea005aec74eb1e11656961f0fb11323f4f91075580808080a01efae04adc2e970b4af3517581f41ce2ba4ff60492d33696c1e2a5ab70cb55bba03bac3f5124774e41fb6efdd7219530846f9f6441045c4666d2855c6598cfca00a020d7122ffc86cb37228940b5a9441e9fd272a3450245c9130ca3ab00bc1cd6ef80a0047f255205a0f2b0e7d29d490abf02bfb62c3ed201c338bc7f0088fa9c5d77eda069fecc766fcb2df04eb3a834b1f4ba134df2be114479e251d9cc9b6ba493077b80a094c3ed6a7ef63a6a67e46cc9876b9b1882eeba3d28e6d61bb15cdfb207d077e180f843a03e077f3dfd0489e70c68282ced0126c62fcef50acdcb7f57aa4552b87b456b11a1a05dc044e92e82db28c96fd98edd502949612b06e8da6dd74664a43a5ed857b298").to_vec(),
                account_storage_root: [0u8;32].into(),
            }
        );
        raw_header.trusted_height = Some(optimism_ibc_proto::ibc::core::client::v1::Height {
            revision_number: 0,
            revision_height: 1,
        });
        let header = Header::<{ ethereum_consensus::preset::minimal::PRESET.SYNC_COMMITTEE_SIZE} >::try_from(raw_header).unwrap();
        let err = header.verify_l2(1, [1u8; 32].into()).unwrap_err();
        match err {
            Error::UnexpectedTrustedOutputRoot(_, _) => {}
            _ => panic!("Unexpected error: {:?}", err),
        }
    }

    #[test]
    fn test_l2_header_verify_derivation_error() {
        let mut raw_header = get_empty_raw_header();
        raw_header.deterministic_to_latest = vec![get_raw_l1_header()];
        raw_header.derivation = Some(RawDerivation {
            agreed_l2_output_root: [0u8; 32].into(),
            l2_output_root: [0u8; 32].into(),
            l2_block_number: 2,
        });
        raw_header.account_update = Some(
            RawAccountUpdate {
                account_proof: hex!("f90159f901118080a0143145e818eeff83817419a6632ea193fd1acaa4f791eb17282f623f38117f56a0e6ee0a993a7254ee9253d766ea005aec74eb1e11656961f0fb11323f4f91075580808080a01efae04adc2e970b4af3517581f41ce2ba4ff60492d33696c1e2a5ab70cb55bba03bac3f5124774e41fb6efdd7219530846f9f6441045c4666d2855c6598cfca00a020d7122ffc86cb37228940b5a9441e9fd272a3450245c9130ca3ab00bc1cd6ef80a0047f255205a0f2b0e7d29d490abf02bfb62c3ed201c338bc7f0088fa9c5d77eda069fecc766fcb2df04eb3a834b1f4ba134df2be114479e251d9cc9b6ba493077b80a094c3ed6a7ef63a6a67e46cc9876b9b1882eeba3d28e6d61bb15cdfb207d077e180f843a03e077f3dfd0489e70c68282ced0126c62fcef50acdcb7f57aa4552b87b456b11a1a05dc044e92e82db28c96fd98edd502949612b06e8da6dd74664a43a5ed857b298").to_vec(),
                account_storage_root: [0u8;32].into(),
            }
        );
        raw_header.trusted_height = Some(optimism_ibc_proto::ibc::core::client::v1::Height {
            revision_number: 0,
            revision_height: 1,
        });
        let header = Header::<{ ethereum_consensus::preset::minimal::PRESET.SYNC_COMMITTEE_SIZE} >::try_from(raw_header).unwrap();
        let err = header
            .verify_l2(1, header.derivation.agreed_l2_output_root)
            .unwrap_err();
        match err {
            Error::DerivationError(_, _, _) => {}
            _ => panic!("Unexpected error: {:?}", err),
        }
    }
}
