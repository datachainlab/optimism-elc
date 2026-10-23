use crate::errors::Error;
use crate::l1::{L1Config, L1ConsensusState, L1Header, Misbehaviour as L1Misbehaviour};
use crate::misc::to_lcp_height;
use alloc::vec::Vec;
use alloy_consensus::Header;
use alloy_primitives::private::alloy_rlp::Decodable;
use alloy_primitives::{keccak256, B256};
use core::str::FromStr;
use ethereum_consensus::types::{Address, H256};
use ethereum_light_client_types::commitment::decode_eip1184_rlp_proof;
use ethereum_light_client_types::commitment::verify_account_storage;
use ethereum_light_client_types::consensus::AccountUpdateInfo;
use ethereum_light_client_verifier::execution::ExecutionVerifier;
use kona_protocol::{OutputRoot, Predeploys};
use light_client::types::{Any, ClientId, Height};
use optimism_ibc_proto::google::protobuf::Any as IBCAny;
use optimism_ibc_proto::ibc::lightclients::optimism::v1::FaultDisputeGameConfig as RawFaultDisputeGameConfig;
use optimism_ibc_proto::ibc::lightclients::optimism::v1::FaultDisputeGameProof as RawFaultDisputeGameProof;
use optimism_ibc_proto::ibc::lightclients::optimism::v1::Misbehaviour as RawL2Misbehaviour;
use prost::Message;

pub const OPTIMISM_MISBEHAVIOUR_TYPE_URL: &str = "/ibc.lightclients.optimism.v1.Misbehaviour";

fn u64_to_bytes32(n: u64) -> [u8; 32] {
    left_pad(n.to_be_bytes().to_vec())
}

fn left_pad(n: Vec<u8>) -> [u8; 32] {
    let mut buf = [0u8; 32];
    buf[32 - n.len()..].copy_from_slice(&n);
    buf
}

/// slot = keccak256([key, mappingSlot])
fn calculate_mapping_slot_bytes(key_bytes: &[u8], mapping_slot: u64) -> B256 {
    let mapping_slot_bytes = u64_to_bytes32(mapping_slot);

    let mut concatenated = Vec::with_capacity(key_bytes.len() + mapping_slot_bytes.len());
    concatenated.extend_from_slice(key_bytes);
    concatenated.extend_from_slice(&mapping_slot_bytes);

    keccak256(&concatenated)
}

/// The preimage of a Super Root: the `extraData` of a Super Root dispute game.
///
/// `version(1) || timestamp(8) || (chainId(32) || outputRoot(32))*n`
/// as produced by `Encoding.encodeSuperRootProof` in contracts-bedrock.
///
/// `SuperFaultDisputeGame.initialize` reverts with `BadExtraData` unless
/// `keccak256(extraData) == rootClaim`, so hashing these raw bytes yields the game's
/// root claim. `decodeSuperRootProof` accepts exactly the encodings this type accepts,
/// which makes the encode/decode round trip byte identical.
#[derive(Clone, Debug)]
pub struct SuperRootProof {
    raw: Vec<u8>,
}

impl SuperRootProof {
    const VERSION: u8 = 0x01;
    /// version(1) + timestamp(8)
    const HEADER_SIZE: usize = 9;
    /// chainId(32) + outputRoot(32)
    const ENTRY_SIZE: usize = 64;

    pub fn new(raw: Vec<u8>) -> Result<Self, Error> {
        if raw.len() < Self::HEADER_SIZE {
            return Err(Error::UnexpectedSuperRootProofSize(raw.len()));
        }
        if raw[0] != Self::VERSION {
            return Err(Error::UnexpectedSuperRootProofVersion(raw[0]));
        }
        let entries = raw.len() - Self::HEADER_SIZE;
        if entries == 0 || !entries.is_multiple_of(Self::ENTRY_SIZE) {
            return Err(Error::UnexpectedSuperRootProofSize(raw.len()));
        }
        Ok(Self { raw })
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.raw
    }

    /// The game's `rootClaim`.
    pub fn root_claim(&self) -> B256 {
        keccak256(&self.raw)
    }

    /// The game's `l2SequenceNumber`: the timestamp the super root was proposed for.
    pub fn timestamp(&self) -> u64 {
        let mut timestamp = [0u8; 8];
        timestamp.copy_from_slice(&self.raw[1..Self::HEADER_SIZE]);
        u64::from_be_bytes(timestamp)
    }

    /// The output root this super root commits to for `chain_id`, equivalent to
    /// `SuperFaultDisputeGame.rootClaimByChainId`.
    pub fn output_root(&self, chain_id: u64) -> Result<B256, Error> {
        for entry in self.raw[Self::HEADER_SIZE..].chunks_exact(Self::ENTRY_SIZE) {
            // chain ids are encoded as uint256: anything that overflows u64 is not ours
            let (upper, lower) = entry[..32].split_at(24);
            if upper.iter().any(|byte| *byte != 0) {
                continue;
            }
            let mut id = [0u8; 8];
            id.copy_from_slice(lower);
            if u64::from_be_bytes(id) == chain_id {
                return Ok(B256::from_slice(&entry[32..]));
            }
        }
        Err(Error::ChainIdNotFoundInSuperRootProof(chain_id))
    }
}

/// Calculate the game UUID.
/// https://github.com/ethereum-optimism/optimism/blob/op-node/v1.19.5/packages/contracts-bedrock/src/dispute/DisputeGameFactory.sol#L233
/// `keccak256(abi.encode(gameType, rootClaim, extraData))`
fn get_game_uuid(source_game_type: u64, super_root_proof: &SuperRootProof) -> B256 {
    let extra_data = super_root_proof.as_bytes();

    // Build the source array
    let mut source = Vec::new();

    source.extend_from_slice(u64_to_bytes32(source_game_type).as_slice());
    source.extend_from_slice(super_root_proof.root_claim().as_slice());

    // extra data part
    // `extraData` is a dynamic `bytes`, so abi.encode lays out the offset of the
    // dynamic part, its length, and then the data right-padded with zeros to a
    // multiple of 32 bytes:
    // 0000000000000000000000000000000000000000000000000000000000000060  // extra_offset
    // 0000000000000000000000000000000000000000000000000000000000000049  // extra_length (73)
    // 01000000006a882b1d000000000000000000000000000000000000000000000  // extraData ..
    // 00000000020d5e467d6810b57045b03b4a810ca7f0f946b01d7dfef59263f0b7  // ..
    // a2c23c83a5354e900000000000000000000000000000000000000000000000000  // .. + padding

    // start position of extra_data length
    // 32 (gameType) + 32(rootClaim) + extraOffset(32)
    let extra_offset = u64_to_bytes32(96);
    let extra_len = u64_to_bytes32(extra_data.len() as u64);
    source.extend_from_slice(extra_offset.as_slice());
    source.extend_from_slice(extra_len.as_slice());
    source.extend_from_slice(extra_data);
    let padding = (32 - extra_data.len() % 32) % 32;
    source.resize(source.len() + padding, 0);

    keccak256(&source)
}

/// https://github.com/ethereum-optimism/optimism/blob/b2a5bc202c267ea91176676e43e8e9b217d20680/packages/contracts-bedrock/src/dispute/lib/LibUDT.sol#L108
fn unpack_game_id(game_id: [u8; 32]) -> (Vec<u8>, Vec<u8>, [u8; 20]) {
    let game_type = game_id[0..4].to_vec();
    let timestamp = game_id[4..12].to_vec();
    let mut game_proxy = [0u8; 20];
    game_proxy.copy_from_slice(&game_id[12..32]);
    (game_type, timestamp, game_proxy)
}

#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct FaultDisputeGameConfig {
    dispute_game_factory_address: Address,
    dispute_game_factory_target_storage_slot: u32,
    fault_dispute_game_status_slot: u32,
    fault_dispute_game_status_slot_offset: u32,
    fault_dispute_game_created_at_slot_offset: u32,
    status_defender_win: u8,
}

impl TryFrom<RawFaultDisputeGameConfig> for FaultDisputeGameConfig {
    type Error = Error;

    fn try_from(value: RawFaultDisputeGameConfig) -> Result<Self, Self::Error> {
        Ok(Self {
            dispute_game_factory_address: Address::try_from(
                value.dispute_game_factory_address.as_slice(),
            )
            .map_err(Error::UnexpectedDisputeGameFactoryAddress)?,
            dispute_game_factory_target_storage_slot: value
                .dispute_game_factory_target_storage_slot,
            fault_dispute_game_status_slot: value.fault_dispute_game_status_slot,
            fault_dispute_game_status_slot_offset: value.fault_dispute_game_status_slot_offset,
            fault_dispute_game_created_at_slot_offset: value
                .fault_dispute_game_created_at_slot_offset,
            status_defender_win: u8::try_from(value.status_defender_win)
                .map_err(|_| Error::UnexpectedStatusDefenderWin(value.status_defender_win))?,
        })
    }
}

impl From<FaultDisputeGameConfig> for RawFaultDisputeGameConfig {
    fn from(value: FaultDisputeGameConfig) -> Self {
        Self {
            dispute_game_factory_address: value.dispute_game_factory_address.0.to_vec(),
            dispute_game_factory_target_storage_slot: value
                .dispute_game_factory_target_storage_slot,
            fault_dispute_game_status_slot: value.fault_dispute_game_status_slot,
            fault_dispute_game_status_slot_offset: value.fault_dispute_game_status_slot_offset,
            fault_dispute_game_created_at_slot_offset: value
                .fault_dispute_game_created_at_slot_offset,
            status_defender_win: value.status_defender_win as u32,
        }
    }
}

#[derive(Clone, Debug)]
pub struct FaultDisputeGameProof {
    /// Finalized and verified L1 header
    state_root: B256,
    /// Proof of DisputeGameFactoryProxy
    dispute_game_factory_account: AccountUpdateInfo,
    dispute_game_factory_game_id_proof: Vec<Vec<u8>>,

    /// Proof of FaultDisputeGame
    fault_dispute_game_account: AccountUpdateInfo,
    fault_dispute_game_game_status_proof: Vec<Vec<u8>>,
    fault_dispute_game_source_game_type: u64,
}

impl TryFrom<RawFaultDisputeGameProof> for FaultDisputeGameProof {
    type Error = Error;

    fn try_from(value: RawFaultDisputeGameProof) -> Result<Self, Self::Error> {
        let state_root = B256::try_from(value.state_root.as_slice())
            .map_err(|_| Error::UnexpectedStateRoot(value.state_root))?;
        let dispute_game_factory_account = AccountUpdateInfo::try_from(
            value
                .dispute_game_factory_account
                .ok_or(Error::proto_missing("dispute_game_factory_account"))?,
        )?;
        let dispute_game_factory_game_id_proof =
            decode_eip1184_rlp_proof(value.dispute_game_factory_game_id_proof)?;

        let fault_dispute_game_account = AccountUpdateInfo::try_from(
            value
                .fault_dispute_game_account
                .ok_or(Error::proto_missing("fault_dispute_game_account"))?,
        )?;
        let fault_dispute_game_game_status_proof =
            decode_eip1184_rlp_proof(value.fault_dispute_game_game_status_proof)?;

        Ok(Self {
            state_root,
            dispute_game_factory_account,
            dispute_game_factory_game_id_proof,
            fault_dispute_game_account,
            fault_dispute_game_game_status_proof,
            fault_dispute_game_source_game_type: value.fault_dispute_game_source_game_type,
        })
    }
}

#[derive(Clone, Debug)]
pub struct GameStatus {
    packing_slot_value: [u8; 32],
    dispute_game_address: Address,
}

impl FaultDisputeGameProof {
    fn get_game_id(
        &self,
        fault_dispute_game_config: &FaultDisputeGameConfig,
        super_root_proof: &SuperRootProof,
    ) -> Result<Option<Vec<u8>>, Error> {
        let state_root: H256 = self.state_root.0.into();
        // Ensure valid account proof
        verify_account_storage(
            &ExecutionVerifier,
            state_root,
            &fault_dispute_game_config.dispute_game_factory_address,
            &self.dispute_game_factory_account,
        )?;

        // Extract game id from DisputeGameFactoryProxy by the super root proof. Only a
        // game created with exactly this (gameType, keccak256(preimage), preimage) has
        // this UUID, so the preimage is pinned to on-chain state.
        let game_uuid = get_game_uuid(self.fault_dispute_game_source_game_type, super_root_proof);
        let game_id_key = calculate_mapping_slot_bytes(
            game_uuid.as_slice(),
            fault_dispute_game_config.dispute_game_factory_target_storage_slot as u64,
        );
        ExecutionVerifier
            .verify(
                self.dispute_game_factory_account.account_storage_root,
                game_id_key.as_slice(),
                self.dispute_game_factory_game_id_proof.clone(),
            )
            .map_err(|err| Error::UnexpectedDisputeGameFactoryProxyProof {
                proof: self.clone(),
                game_type: self.fault_dispute_game_source_game_type,
                root_claim: super_root_proof.root_claim(),
                err: Some(err),
            })
    }

    fn get_game_status(
        &self,
        fault_dispute_game_config: &FaultDisputeGameConfig,
        super_root_proof: &SuperRootProof,
    ) -> Result<GameStatus, Error> {
        let state_root: H256 = self.state_root.0.into();
        let game_id = self.get_game_id(fault_dispute_game_config, super_root_proof)?;
        let game_id = game_id.ok_or_else(|| Error::UnexpectedDisputeGameFactoryProxyProof {
            proof: self.clone(),
            game_type: self.fault_dispute_game_source_game_type,
            root_claim: super_root_proof.root_claim(),
            err: None,
        })?;

        // Ensure game is resolved with DEFENDER_WIN status
        let (_, _, fault_dispute_game_address) = unpack_game_id(left_pad(game_id));
        verify_account_storage(
            &ExecutionVerifier,
            state_root,
            &Address(fault_dispute_game_address),
            &self.fault_dispute_game_account,
        )?;
        let status_key =
            u64_to_bytes32(fault_dispute_game_config.fault_dispute_game_status_slot as u64);
        let packing_slot_value = ExecutionVerifier
            .verify(
                self.fault_dispute_game_account.account_storage_root,
                status_key.as_slice(),
                self.fault_dispute_game_game_status_proof.clone(),
            )
            .map_err(|err| Error::UnexpectedFaultDisputeGameProof {
                proof: self.clone(),
                address: Address(fault_dispute_game_address),
                err: Some(err),
            })?;
        let packing_slot_value =
            packing_slot_value.ok_or_else(|| Error::UnexpectedFaultDisputeGameProof {
                proof: self.clone(),
                address: Address(fault_dispute_game_address),
                err: None,
            })?;
        Ok(GameStatus {
            packing_slot_value: left_pad(packing_slot_value),
            dispute_game_address: Address(fault_dispute_game_address),
        })
    }

    pub fn verify_game_created(
        &self,
        fault_dispute_game_config: &FaultDisputeGameConfig,
        super_root_proof: &SuperRootProof,
        l1_timestamp: u64,
    ) -> Result<(), Error> {
        let game_status = self.get_game_status(fault_dispute_game_config, super_root_proof)?;
        let offset = fault_dispute_game_config.fault_dispute_game_created_at_slot_offset as usize;
        let created_at = &game_status.packing_slot_value[offset..];
        let created_at =
            u64::from_be_bytes(created_at.try_into().map_err(Error::UnexpectedCreatedAt)?);
        if l1_timestamp != created_at {
            return Err(Error::UnexpectedGameCreatedAt(created_at, l1_timestamp));
        }
        Ok(())
    }

    pub fn verify_resolved_status(
        &self,
        fault_dispute_game_config: &FaultDisputeGameConfig,
        super_root_proof: &SuperRootProof,
    ) -> Result<(), Error> {
        let game_status = self.get_game_status(fault_dispute_game_config, super_root_proof)?;

        let status = game_status.packing_slot_value
            [fault_dispute_game_config.fault_dispute_game_status_slot_offset as usize];
        if status != fault_dispute_game_config.status_defender_win {
            return Err(Error::UnexpectedResolvedStatus {
                proof: self.clone(),
                status,
                address: game_status.dispute_game_address,
                packing_slot_value: game_status.packing_slot_value,
            });
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct HeaderWithMessagePasserAccount {
    header: Header,
    account: AccountUpdateInfo,
}

impl HeaderWithMessagePasserAccount {
    pub fn compute_output_root(&self) -> Result<B256, Error> {
        Self::compute_output_root_from_state_and_hash(
            &self.account,
            &self.header.state_root,
            self.header.hash_slow(),
        )
    }

    fn compute_output_root_from_state_and_hash(
        account: &AccountUpdateInfo,
        state_root: &B256,
        hash: B256,
    ) -> Result<B256, Error> {
        // Ensure the account storage root matches the expected state root
        verify_account_storage(
            &ExecutionVerifier,
            state_root.0.into(),
            &Address(Predeploys::L2_TO_L1_MESSAGE_PASSER.0 .0),
            account,
        )?;

        // Compute the output root from the account storage root and header hash
        Ok(OutputRoot::from_parts(
            state_root.0.into(),
            account.account_storage_root.0.into(),
            hash,
        )
        .hash())
    }
}

#[derive(Clone, Debug)]
pub struct L2HeaderHistory {
    first: HeaderWithMessagePasserAccount,
    last: HeaderWithMessagePasserAccount,
}

impl L2HeaderHistory {
    fn new(
        value: Vec<Vec<u8>>,
        first_mp_account: AccountUpdateInfo,
        last_mp_account: AccountUpdateInfo,
    ) -> Result<Self, Error> {
        let headers = decode_headers(value)?;
        Ok(Self {
            first: HeaderWithMessagePasserAccount {
                header: headers.first().ok_or(Error::NoHeaderFound)?.clone(),
                account: first_mp_account,
            },
            last: HeaderWithMessagePasserAccount {
                header: headers.last().ok_or(Error::NoHeaderFound)?.clone(),
                account: last_mp_account,
            },
        })
    }
}

#[derive(Clone, Debug)]
struct ResolvedData<const SYNC_COMMITTEE_SIZE: usize> {
    /// The preimage of the resolved game's root claim. It carries both the game's
    /// l2SequenceNumber (a timestamp) and the output root claimed for each chain.
    super_root_proof: SuperRootProof,
    fault_dispute_game_factory_proof: FaultDisputeGameProof,
    latest_l1_header: L1Header<SYNC_COMMITTEE_SIZE>,
}

#[derive(Clone, Debug)]
pub struct L2FutureMisbehaviour<const SYNC_COMMITTEE_SIZE: usize> {
    resolved: ResolvedData<SYNC_COMMITTEE_SIZE>,
    submitted_l1_number: u64,
    submitted_l1_timestamp: u64,
    submitted_l1_proof: FaultDisputeGameProof,
}

impl<const SYNC_COMMITTEE_SIZE: usize> L2FutureMisbehaviour<SYNC_COMMITTEE_SIZE> {
    pub fn verify(
        &self,
        now: u64,
        l1_config: &L1Config,
        fault_dispute_game_config: &FaultDisputeGameConfig,
        l1_cons_state: &L1ConsensusState,
        consensus_l2_timestamp: u64,
        consensus_l1_origin: u64,
    ) -> Result<(), Error> {
        self.resolved
            .latest_l1_header
            .verify(now, l1_config, l1_cons_state)?;

        // Ensure the output is resolved with DEFENDER_WIN
        self.resolved
            .fault_dispute_game_factory_proof
            .verify_resolved_status(fault_dispute_game_config, &self.resolved.super_root_proof)?;

        // Ensure submitted_l1_timestamp is the timestamp which the game was created at
        self.submitted_l1_proof.verify_game_created(
            fault_dispute_game_config,
            &self.resolved.super_root_proof,
            self.submitted_l1_timestamp,
        )?;

        // Ensure trusted l1 origin is greater than the submitted l1 block number
        if self.submitted_l1_number >= consensus_l1_origin {
            return Err(Error::UnexpectedPastL1Header(
                consensus_l1_origin,
                self.submitted_l1_number,
            ));
        }

        // The game resolved for a super root beyond the trusted state: its
        // l2SequenceNumber is the timestamp of the proposed super root.
        let resolved_l2_timestamp = self.resolved.super_root_proof.timestamp();
        if consensus_l2_timestamp >= resolved_l2_timestamp {
            return Err(Error::UnexpectedMisbehaviourTimestamp(
                consensus_l2_timestamp,
                resolved_l2_timestamp,
            ));
        }

        // Misbehaviour detected
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct L2PastMisbehaviour<const SYNC_COMMITTEE_SIZE: usize> {
    resolved: ResolvedData<SYNC_COMMITTEE_SIZE>,
    l2_header_history: L2HeaderHistory,
}

impl<const SYNC_COMMITTEE_SIZE: usize> L2PastMisbehaviour<SYNC_COMMITTEE_SIZE> {
    pub fn verify(
        &self,
        now: u64,
        l1_config: &L1Config,
        fault_dispute_game_config: &FaultDisputeGameConfig,
        l1_cons_state: &L1ConsensusState,
        chain_id: u64,
        consensus_output_root: B256,
    ) -> Result<(), Error> {
        self.resolved
            .latest_l1_header
            .verify(now, l1_config, l1_cons_state)?;

        // Ensure the output is resolved with DEFENDER_WIN
        self.resolved
            .fault_dispute_game_factory_proof
            .verify_resolved_status(fault_dispute_game_config, &self.resolved.super_root_proof)?;

        // Ensure the headers for calculating contradict output can be traversed from consensus state
        let trusted_output_root = self.l2_header_history.first.compute_output_root()?;
        if trusted_output_root != consensus_output_root {
            return Err(Error::UnexpectedTrustedOutputRoot(
                trusted_output_root,
                consensus_output_root,
            ));
        }

        // The output root the resolved super root claims for this chain
        let resolved_output_root = self.resolved.super_root_proof.output_root(chain_id)?;
        // Calculate the resolved output from cons state
        let contradict_resolved_output_root = self.l2_header_history.last.compute_output_root()?;
        if contradict_resolved_output_root == resolved_output_root {
            return Err(Error::UnexpectedMisbehaviourOutput(
                contradict_resolved_output_root,
            ));
        }

        // Misbehaviour detected
        Ok(())
    }
}

#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug)]
pub enum Verifier<const SYNC_COMMITTEE_SIZE: usize> {
    Future(L2FutureMisbehaviour<SYNC_COMMITTEE_SIZE>),
    Past(L2PastMisbehaviour<SYNC_COMMITTEE_SIZE>),
}

#[derive(Clone, Debug)]
pub struct L2Misbehaviour<const SYNC_COMMITTEE_SIZE: usize> {
    client_id: ClientId,
    trusted_height: Height,

    verifier: Verifier<SYNC_COMMITTEE_SIZE>,
}

impl<const SYNC_COMMITTEE_SIZE: usize> L2Misbehaviour<SYNC_COMMITTEE_SIZE> {
    pub fn verifier(&self) -> &Verifier<SYNC_COMMITTEE_SIZE> {
        &self.verifier
    }
}

impl<const SYNC_COMMITTEE_SIZE: usize> TryFrom<RawL2Misbehaviour>
    for L2Misbehaviour<SYNC_COMMITTEE_SIZE>
{
    type Error = Error;

    fn try_from(raw: RawL2Misbehaviour) -> Result<Self, Self::Error> {
        let client_id = ClientId::from_str(&raw.client_id).map_err(Error::UnexpectedClientId)?;
        let trusted_height = raw
            .trusted_height
            .ok_or(Error::proto_missing("trusted_height"))?;

        let proto_fdg_factory_proof = raw
            .fault_dispute_game_proof
            .ok_or(Error::proto_missing("fault_dispute_game_proof"))?;

        let super_root_proof = SuperRootProof::new(raw.super_root_proof)?;

        let fault_dispute_game_factory_proof =
            FaultDisputeGameProof::try_from(proto_fdg_factory_proof)?;

        let latest_l1_header = L1Header::<SYNC_COMMITTEE_SIZE>::try_from(
            raw.latest_l1_header
                .ok_or(Error::proto_missing("latest_l1_header"))?,
        )?;

        let latest_state_root: B256 = latest_l1_header.execution_update.state_root.0.into();
        if fault_dispute_game_factory_proof.state_root != latest_state_root {
            return Err(Error::UnexpectedL1HeaderStateRoot(
                fault_dispute_game_factory_proof.state_root,
                latest_state_root,
            ));
        }

        // Check for future game verification
        let submitted_l1_proof = if let Some(submitted_l1_proof) = raw.submitted_l1_proof {
            Some(FaultDisputeGameProof::try_from(submitted_l1_proof)?)
        } else {
            None
        };
        // For future check
        if let Some(submitted_l1_proof) = submitted_l1_proof {
            let l1_headers = decode_headers(raw.l1_header_history)?;

            // Ensure collect order
            let submitted = &l1_headers.last().ok_or(Error::NoHeaderFound)?;
            let latest = l1_headers.first().ok_or(Error::NoHeaderFound)?;
            if latest_l1_header.execution_update.block_number.0 != latest.number {
                return Err(Error::UnexpectedL1HeaderNumber(
                    latest_l1_header.execution_update.block_number.0,
                    latest.number,
                ));
            }
            if submitted_l1_proof.state_root != submitted.state_root {
                return Err(Error::UnexpectedSubmittedL1HeaderStateRoot(
                    submitted_l1_proof.state_root,
                    submitted.state_root,
                ));
            }
            Ok(Self {
                client_id,
                trusted_height: Height::from(trusted_height),
                verifier: Verifier::Future(L2FutureMisbehaviour {
                    resolved: ResolvedData {
                        super_root_proof,
                        fault_dispute_game_factory_proof,
                        latest_l1_header,
                    },
                    submitted_l1_number: submitted.number,
                    submitted_l1_timestamp: submitted.timestamp,
                    submitted_l1_proof,
                }),
            })
        } else {
            // For past check
            let proto_trusted_l2_to_l1_message_passer_account = raw
                .first_l2_to_l1_message_passer_account
                .ok_or(Error::proto_missing(
                    "first_l2_to_l1_message_passer_account",
                ))?;
            let proto_resolved_l2_to_l1_message_passer_account = raw
                .last_l2_to_l1_message_passer_account
                .ok_or(Error::proto_missing("last_l2_to_l1_message_passer_account"))?;

            let first_l2_to_l1_message_passer_account =
                AccountUpdateInfo::try_from(proto_trusted_l2_to_l1_message_passer_account)?;
            let last_l2_to_l1_message_passer_account =
                AccountUpdateInfo::try_from(proto_resolved_l2_to_l1_message_passer_account)?;

            let l2_header_history = L2HeaderHistory::new(
                raw.l2_header_history,
                first_l2_to_l1_message_passer_account,
                last_l2_to_l1_message_passer_account,
            )?;
            // The resolved super root is identified by a timestamp, so the last header of
            // the history must be the L2 block that super root was proposed for.
            let resolved_l2_timestamp = super_root_proof.timestamp();
            if l2_header_history.last.header.timestamp != resolved_l2_timestamp {
                return Err(Error::UnexpectedResolvedL2Timestamp(
                    resolved_l2_timestamp,
                    l2_header_history.last.header.timestamp,
                ));
            }
            Ok(Self {
                client_id,
                trusted_height: Height::from(trusted_height),
                verifier: Verifier::Past(L2PastMisbehaviour {
                    resolved: ResolvedData {
                        super_root_proof,
                        fault_dispute_game_factory_proof,
                        latest_l1_header,
                    },
                    l2_header_history,
                }),
            })
        }
    }
}

#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug)]
pub enum Misbehaviour<const SYNC_COMMITTEE_SIZE: usize> {
    L2(L2Misbehaviour<SYNC_COMMITTEE_SIZE>),
    L1(L1Misbehaviour<SYNC_COMMITTEE_SIZE>),
}

impl<const SYNC_COMMITTEE_SIZE: usize> Misbehaviour<SYNC_COMMITTEE_SIZE> {
    pub fn trusted_height(&self) -> Height {
        match self {
            Misbehaviour::L2(misbehaviour) => misbehaviour.trusted_height,
            Misbehaviour::L1(misbehaviour) => {
                to_lcp_height(misbehaviour.trusted_sync_committee.height)
            }
        }
    }

    pub fn client_id(&self) -> &ClientId {
        match self {
            Misbehaviour::L2(misbehaviour) => &misbehaviour.client_id,
            Misbehaviour::L1(misbehaviour) => &misbehaviour.client_id,
        }
    }
}

impl<const L1_SYNC_COMMITTEE_SIZE: usize> TryFrom<Any> for Misbehaviour<L1_SYNC_COMMITTEE_SIZE> {
    type Error = Error;

    fn try_from(any: Any) -> Result<Self, Self::Error> {
        IBCAny::from(any).try_into()
    }
}

impl<const SYNC_COMMITTEE_SIZE: usize> TryFrom<IBCAny> for Misbehaviour<SYNC_COMMITTEE_SIZE> {
    type Error = Error;

    fn try_from(raw: IBCAny) -> Result<Self, Self::Error> {
        match raw.type_url.as_str() {
            OPTIMISM_MISBEHAVIOUR_TYPE_URL => {
                let raw = RawL2Misbehaviour::decode(raw.value.as_slice())
                    .map_err(Error::ProtoDecodeError)?;
                Ok(Misbehaviour::L2(L2Misbehaviour::try_from(raw)?))
            }
            _ => Ok(Misbehaviour::L1(L1Misbehaviour::try_from(raw)?)),
        }
    }
}

fn decode_headers(value: Vec<Vec<u8>>) -> Result<Vec<Header>, Error> {
    let mut headers: Vec<Header> = Vec::with_capacity(value.len());
    for rlp in value.into_iter() {
        let mut rlp = rlp.as_slice();
        let header = Header::decode(&mut rlp).map_err(Error::UnexpectedHeaderRLPError)?;
        headers.push(header);
    }

    // Ensure collect header relation
    for (index, header) in headers.iter().enumerate() {
        if index == headers.len() - 1 {
            break;
        }
        let parent = &headers[index + 1];
        if header.parent_hash != parent.hash_slow() || header.number != parent.number + 1 {
            return Err(Error::UnexpectedHeaderRelation {
                expected_parent_hash: header.parent_hash,
                actual_parent_hash: parent.hash_slow(),
                header_number: header.number,
                parent_number: parent.number,
            });
        }
    }
    Ok(headers)
}

#[cfg(test)]
mod test {
    use crate::errors::Error;
    use crate::misbehaviour::{
        get_game_uuid, FaultDisputeGameConfig, FaultDisputeGameProof,
        HeaderWithMessagePasserAccount, L2HeaderHistory, L2Misbehaviour, SuperRootProof,
    };
    use alloc::string::ToString;
    use alloc::vec;
    use alloc::vec::Vec;
    use alloy_consensus::Header;
    use alloy_primitives::private::alloy_rlp::Decodable;
    use alloy_primitives::{hex, B256};
    use ethereum_consensus::types::Address;
    use ethereum_light_client_types::consensus::AccountUpdateInfo;
    use ethereum_light_client_types::errors::Error as EthLightClientTypesError;
    use optimism_ibc_proto::ibc::core::client::v1::Height;
    use optimism_ibc_proto::ibc::lightclients::ethereum::v1::{
        AccountUpdate as RawAccountUpdate, BeaconBlockHeader, ConsensusUpdate, ExecutionUpdate,
        SyncAggregate, SyncCommittee, TrustedSyncCommittee,
    };
    use optimism_ibc_proto::ibc::lightclients::optimism::v1::FaultDisputeGameProof as RawFaultDisputeGameProof;
    use optimism_ibc_proto::ibc::lightclients::optimism::v1::L1Header;
    use optimism_ibc_proto::ibc::lightclients::optimism::v1::Misbehaviour as RawL2Misbehaviour;
    use rlp::EMPTY_LIST_RLP;

    impl Default for FaultDisputeGameConfig {
        fn default() -> Self {
            Self {
                dispute_game_factory_address: Address(hex!(
                    "defde373865506309e2ab84a41fdecc584b66de1"
                )),
                dispute_game_factory_target_storage_slot: 103,
                fault_dispute_game_status_slot: 0,
                fault_dispute_game_status_slot_offset: 15,
                fault_dispute_game_created_at_slot_offset: 24,
                status_defender_win: 2,
            }
        }
    }

    // generated from the kurtosis devnet (op-node/v1.19.5, game type 5)
    //   factory  = 0xdefde373865506309e2ab84a41fdecc584b66de1
    //   game     = 0x90FdfEDC9004fcDD53ddFF0E081F7a42BF99227f
    //   L1 block = 1782
    //   uuid     = 0x33f996320179a7b085b4054a288dd4406822340571e77e584e51821552f5f33f
    //   slot     = 0xa3f44a9a1b4ef3c7f9982524678ad004eebf7f4064f95d1d269e856d2056ce9a
    fn default_super_root_proof() -> SuperRootProof {
        SuperRootProof::new(
            hex!("01000000006a8a9118000000000000000000000000000000000000000000000000000000000020d5e4793bc018d07a638b021d7741090a1bd95024da62b18b83b0e3b73b60c3b0e592").to_vec(),
        )
        .unwrap()
    }

    /// l2SequenceNumber() of the game the fixture was taken from
    const DEFAULT_SUPER_ROOT_TIMESTAMP: u64 = 1787466008;
    /// createdAt() of the game the fixture was taken from
    const DEFAULT_GAME_CREATED_AT: u64 = 1787466044;
    /// the devnet's L2 chain id
    const DEFAULT_CHAIN_ID: u64 = 2151908;

    #[test]
    fn test_super_root_proof_accessors() {
        let proof = default_super_root_proof();
        assert_eq!(proof.timestamp(), DEFAULT_SUPER_ROOT_TIMESTAMP);
        // SuperFaultDisputeGame.initialize enforces this equality on chain
        assert_eq!(
            proof.root_claim(),
            B256::from(hex!(
                "ad7e83240a47f7be1efe065d33cbd44e3db15e6c163a102b37a4ee76b7e0ce31"
            ))
        );
        // rootClaimByChainId
        assert_eq!(
            proof.output_root(DEFAULT_CHAIN_ID).unwrap(),
            B256::from(hex!(
                "793bc018d07a638b021d7741090a1bd95024da62b18b83b0e3b73b60c3b0e592"
            ))
        );
        match proof.output_root(DEFAULT_CHAIN_ID + 1).unwrap_err() {
            Error::ChainIdNotFoundInSuperRootProof(chain_id) => {
                assert_eq!(chain_id, DEFAULT_CHAIN_ID + 1)
            }
            err => panic!("Unexpected error, got: {:?}", err),
        }
    }

    #[test]
    fn test_super_root_proof_error() {
        let valid = default_super_root_proof().as_bytes().to_vec();

        // unsupported version
        let mut bad_version = valid.clone();
        bad_version[0] = 0x02;
        match SuperRootProof::new(bad_version).unwrap_err() {
            Error::UnexpectedSuperRootProofVersion(version) => assert_eq!(version, 0x02),
            err => panic!("Unexpected error, got: {:?}", err),
        }

        // no output roots at all
        match SuperRootProof::new(valid[..9].to_vec()).unwrap_err() {
            Error::UnexpectedSuperRootProofSize(size) => assert_eq!(size, 9),
            err => panic!("Unexpected error, got: {:?}", err),
        }

        // truncated header
        match SuperRootProof::new(valid[..8].to_vec()).unwrap_err() {
            Error::UnexpectedSuperRootProofSize(size) => assert_eq!(size, 8),
            err => panic!("Unexpected error, got: {:?}", err),
        }

        // partial output root entry
        match SuperRootProof::new(valid[..valid.len() - 1].to_vec()).unwrap_err() {
            Error::UnexpectedSuperRootProofSize(size) => assert_eq!(size, valid.len() - 1),
            err => panic!("Unexpected error, got: {:?}", err),
        }
    }

    #[test]
    fn test_get_game_uuid() {
        // DisputeGameFactory.getGameUUID(5, rootClaim, extraData) on the devnet
        assert_eq!(
            get_game_uuid(5, &default_super_root_proof()),
            B256::from(hex!(
                "33f996320179a7b085b4054a288dd4406822340571e77e584e51821552f5f33f"
            ))
        );
    }

    fn default_fault_dispute_game_proof() -> FaultDisputeGameProof {
        FaultDisputeGameProof {
            state_root: hex!("fbb30d90a4c8b85379d760a7de1eab9f8552db81c0abc3b86f06ffbb1118d8b7").into(),
            dispute_game_factory_account: AccountUpdateInfo {
                account_proof: vec![
                        hex!("f90211a0ca8b66e31145859dd0514e892ee0cae8767d35a7fb7cb0c35f2938c614eba847a006d47616df479b46b302f2a8b7ed03cb537f6cf7c551c15421c65db4e00fa97fa00f17c83ba434b06370c0dacdb39f3e27335e66c3dd93ad452d788053a01c5e14a01cf959e3607acf954bc61569011784bdbcfea9473230b3000ad95217f4be060ba01c2f40abbfe2527e287866d34a678666659a722095618b0a233013403ed909d4a0ff9ab42125967e47feb816d853b06fd9a3c0ac23dd4c2211ad818e661dfe8f64a0ec8b7dcb61b18e6082f6ccd8782ff434519efa0576d2584d9e6ec009d05c9801a001d76c17c6804362a07adaf76075031d71008663db3ae7c3d91b59b51bc3bd3ea0127af6b2bcae546de28f78e01973eba47c267c3652f732c7ebd18245f730cf27a07ac63511f3a7e8bcd71bda19433bdedac9381202fd48beb36ea32bdc4b0bb53fa007cd07a418839797ac10448e88c2c9b35001e6d39c5b6ac8aa252d3403cb02daa08f72339302b7d288a0947dc279071a8fcf1e4abe29a81e79bd5246304b6a65f4a03deff6bf48d9d0197163a442464f3a8675b8336dd36dca2ae0d1485bb4dcf26ea046afea0eed44e4b3ebeb802431c1d43bc69a8eae9f00ad3be3f684731c146277a0e25c06d2ecc35a8046753929ffd67dae9b5a5dbac3d5aab8ff4fb05a8f189cd0a0e1afd93ddd554f84a632a47001f8acfebd4eccc1424fb31b9edc229b0967b0f180").into(),
                        hex!("f90191a0bcfafd70d9348d083c7d2e0e4a50b5012fc315c98366d3549628ce4ef1ee27d380a0fce68c85c147e1dd5cee1da2352ac5da170ed3522bfa761cd8ef7962e5171f03a06a1d368c9a1e30938db41f4209da0d86da9a1f4674efe3a2a02a2b0e4273d69da062b30a7e2f19da958d2bf83bb286ddffa9b16320d2406b0282fb980393d8f464a0ad6c9fda68274b5eec7cf0c79cf21c30b3d017c1173e99a47c8e6bfa6f434d9ba00e9d13d988b74d72ca01d86c251cbb997a9ccc211b748e930ad2aa3de4a8f9d780a09171b07a1592254b64c966edfad141a04a5bdfe446c903fcbbae8b38c2253a2ca0153144478bf5484ed685e9167fceadb670c2f382e41f9a690f76a610e1fc26dda0fd04efc67927fbaef3b8defd259a7f78b261bd8a0f93eedf78c0cb27c491083a8080a090c5d06de0e326fe782f9469df01c9028941571dffbbc643aed052feb1cff2f6a0ce35ec89408b73b495e2b3e0ef46d1ec796c7c2e6b05b8ad21547ffa391875c4a060b344606926b3f9c295f0f5ce83be210d352ed7ec18f282c420d9a6744ceadb80").into(),
                        hex!("f869a02077be318fadf3a0b1f6929344c2b5550e6af9aeb95ae647d5b6fa1d41625680b846f8441380a0f32c33eb2834bc0c1dea2fb8d4a63a60a4ad4b9058623022964c1fff65f7dddca0fa8c9db6c6cab7108dea276f4cd09d575674eb0852c0fa3187e59e98ef977998").into(),
                ],
                account_storage_root: hex!("f32c33eb2834bc0c1dea2fb8d4a63a60a4ad4b9058623022964c1fff65f7dddc").into(),
            },
            dispute_game_factory_game_id_proof: vec![
                        hex!("f90211a086a95b50868a8ea61ade394cd6e6759f332df8f5ece21844f19732b367f2590fa08c1acdb3ec20c1bcccfc7e94de29a7dd9458b8f62ad78d94207f05121763ab22a020923b7525c3cde69a3dde75a54d1d91e1b404f0cb16768499f8a4d04a2e5cb7a011973b2ea3b23007ce18e23f1ef89dc6532317b825fcefb8ee92da63f75972e5a08d695845aeb9ef33d1bc0ad947786e2c72996fa973b4e44ce7744c14a9dea21fa001c8b5324b0e022e671739f7e8e3996d8d6dd48883b3fbde25a01113100037f8a0fcd3625f7aae64819065522c86cc78f0fd3d9f9d7ac2f35233f3e3c77ef6f2f4a028a6b8e6c104111198ac6e6844432941633fd344c757c21bfcc3b2ac7006337ea039e5e0b1917248e171915def07ab1b7e78383f245ca1ea35bcf39981d80b6b84a057c95544c5a50ed579c979b3233887507cec04825d0a49068ef8225e3ce57b5fa0cb8b50ac44d4e0ee0652d93cd365f468b139862303e1ccf175812d60c062aa38a07fa76f6879bd8e768e62d0efc1ba7c824e1570084d8e8358beb87496f131040ca0236c0d743bc8b54fe3389abb191a126b5ca7fd162768d6d9fbb81487c336a372a0f0ce4801589bbf8252a91d6acc5f02cc96bd8e311bf6f6a6a35780cfcd5506cca02917270ed41399f549f3d36814daa9dd39e03bb075218f50157ef76294dab665a0b927dc28a6e3fe1f8e4004742411440709fde1dd9175f63c478ea077cbb9f88a80").into(),
                        hex!("f90111808080a06732d5cb62e140d0060088caa764883b8084a18e5f618735266da7e606c5f68680a00912a8e2559ddda5939692a77dd578b7701b9120f9677742553bd89b6eafaae08080a069bb0d79cef1a7060a1123b70562d9905728b4f4588ba9486b322269bed8c620a0927f9cad4cddb81c4c4d1d6e5ce4088c1553e0bb48ea723135a76b4abdecf18b80a0472cbd3766e2dd44e2952fca861794b4ce2eb9737c29f576ec45516bfd89ad1ea0bee5f0d1ace29f487309354ffa9e5cd14eeed148543184357d2ebba2b4fddb7fa020b719335ed6a4958362bc8f802ec7f64c502f4307668acf9095dea4370348b480a029b039715878a96f077fc5283ab4395a75a63fec3733dd67e2bf3af9fb0f1cdb80").into(),
                        hex!("f840a0207bef952424a46511e4614935b4d228a34a15999a957a90fb29d9544e292a489e9d05000000006a8a913c90fdfedc9004fcdd53ddff0e081f7a42bf99227f").into(),
            ],
            fault_dispute_game_account: AccountUpdateInfo {
                account_proof: vec![
                        hex!("f90211a0ca8b66e31145859dd0514e892ee0cae8767d35a7fb7cb0c35f2938c614eba847a006d47616df479b46b302f2a8b7ed03cb537f6cf7c551c15421c65db4e00fa97fa00f17c83ba434b06370c0dacdb39f3e27335e66c3dd93ad452d788053a01c5e14a01cf959e3607acf954bc61569011784bdbcfea9473230b3000ad95217f4be060ba01c2f40abbfe2527e287866d34a678666659a722095618b0a233013403ed909d4a0ff9ab42125967e47feb816d853b06fd9a3c0ac23dd4c2211ad818e661dfe8f64a0ec8b7dcb61b18e6082f6ccd8782ff434519efa0576d2584d9e6ec009d05c9801a001d76c17c6804362a07adaf76075031d71008663db3ae7c3d91b59b51bc3bd3ea0127af6b2bcae546de28f78e01973eba47c267c3652f732c7ebd18245f730cf27a07ac63511f3a7e8bcd71bda19433bdedac9381202fd48beb36ea32bdc4b0bb53fa007cd07a418839797ac10448e88c2c9b35001e6d39c5b6ac8aa252d3403cb02daa08f72339302b7d288a0947dc279071a8fcf1e4abe29a81e79bd5246304b6a65f4a03deff6bf48d9d0197163a442464f3a8675b8336dd36dca2ae0d1485bb4dcf26ea046afea0eed44e4b3ebeb802431c1d43bc69a8eae9f00ad3be3f684731c146277a0e25c06d2ecc35a8046753929ffd67dae9b5a5dbac3d5aab8ff4fb05a8f189cd0a0e1afd93ddd554f84a632a47001f8acfebd4eccc1424fb31b9edc229b0967b0f180").into(),
                        hex!("f901d1a005b122a3109846bddaf323d4e6850348f45a0f7e74d24c1671d475e34854747da049772c68352eab4d0f878553b8d61d585797f20f9dca1e5162c03078c472c98fa023160456f6b764d25bb636bd43bc70b3a0ef61b800661fa3a9a221cc3a94355ea040c355a42690b5378f09b645283e594ba684b42b96ff173c80c94b2723560315a0adfefbc23c67de5c89be9885f775f0e1bb37fa159614a393d1a1a009f01a552fa01684d189bbac3ac6a4aecfd43685c40b24760d95687c004f2ab3486c1686d8a1a0cf8063193541030762db90dd2f67697c531e949dabe33f8d608c3a6bb352b0eba0804c437a2c08f59bbe8278c7fda83d0b18ef3f4ff11cd015c99c156477dbc09da003c5801bf244c28c5c430853d6797ee54f7e1a7c384f51d8c9a1dc4cd96cb74fa0753dd5b1654504161b19536bcaa774ac57f5f9c0a113dd4dacb40a2f654d0235a0a5acd0ecfd7dcecd1f7360af116e7dd25617a0205b5f8b369be3ffc784c4f5a9a0648bfa98d63829a6c81bca6c4dd3c805be12f6e5f59318d33b1d5f33b682bf9ba0ad8d5ae00a40b5ed737c67d483472b640149d82a6e191e170d3254e09f62c2fe80a0823a38527672ae42d480369a80b0b9c2ede964cb93668c0487e1341607c5d5ee8080").into(),
                        hex!("f8918080a0682fce7d4aeac07f107d34326d1085b63062b76bddbcdf910eddbae39d7477c480a086e4439b5184455f67ee7bf70e81cc2a8d59d30832ef0846b6b971609b1b2bfb808080a08c70a89bb147e9acba8dabda0927a05728e60fd638dae64b7ff799d4bd432fb5808080a0e6b8407e64b26011591d2d85340a41421b63fca5197492422c4e62fafeef77fb80808080").into(),
                        hex!("f8689f3bc33a435f4dc6a96e6c7025dd6180d361fbdb35f7df54c7a6f65212fb5268b846f8440180a083c94fcff70624e620abfe3469ac5f9ae837620a7c12abbf55d41b00f2cde590a07d8d8d7acbdae5df3c9875280320147a7a346b6f8062f1ac201d6b6f46e5ab12").into(),
                ],
                account_storage_root: hex!("83c94fcff70624e620abfe3469ac5f9ae837620a7c12abbf55d41b00f2cde590").into(),
            },
            fault_dispute_game_game_status_proof: vec![
                        hex!("f7a120290decd9548b62a8d60345a988386fc84ba6bc95484008f6362f93160ef3e5639493010102000000006a8a913c000000006a8a913c").into(),
            ],
            fault_dispute_game_source_game_type: 5,
        }
    }

    #[test]
    fn test_verify_resolved_status_defender_win() {
        let model = default_fault_dispute_game_proof();
        model
            .verify_resolved_status(
                &FaultDisputeGameConfig::default(),
                &default_super_root_proof(),
            )
            .unwrap()
    }

    #[test]
    fn test_verify_resolved_status_error_not_defender_win() {
        let model = default_fault_dispute_game_proof();
        let config = FaultDisputeGameConfig {
            status_defender_win: 1,
            ..Default::default()
        };

        let err = model
            .verify_resolved_status(&config, &default_super_root_proof())
            .unwrap_err();
        match err {
            Error::UnexpectedResolvedStatus { status, .. } => {
                assert_eq!(status, 2);
            }
            _ => panic!("Unexpected error, got: {:?}", err),
        }
    }

    #[test]
    fn test_verify_resolved_status_invalid_factory_account() {
        let mut model = default_fault_dispute_game_proof();
        model.dispute_game_factory_account.account_proof = vec![];

        let err = model
            .verify_resolved_status(
                &FaultDisputeGameConfig::default(),
                &default_super_root_proof(),
            )
            .unwrap_err();
        match err {
            Error::EthLightClientTypesError(EthLightClientTypesError::MptVerification {
                ..
            }) => {}
            _ => panic!("Unexpected error, got: {:?}", err),
        }
    }

    #[test]
    fn test_verify_resolved_status_error_invalid_factory_proof() {
        let model = default_fault_dispute_game_proof();
        // a super root proof for a different timestamp hashes to a different root claim,
        // so its game UUID is not in the factory
        let mut raw = default_super_root_proof().as_bytes().to_vec();
        raw[8] ^= 0x01;
        let err = model
            .verify_resolved_status(
                &FaultDisputeGameConfig::default(),
                &SuperRootProof::new(raw).unwrap(),
            )
            .unwrap_err();
        match err {
            Error::UnexpectedDisputeGameFactoryProxyProof { .. } => {}
            _ => panic!("Unexpected error, got: {:?}", err),
        }
    }

    #[test]
    fn test_verify_resolved_status_error_invalid_game_proof() {
        let mut model = default_fault_dispute_game_proof();
        model.fault_dispute_game_game_status_proof.pop();
        let err = model
            .verify_resolved_status(
                &FaultDisputeGameConfig::default(),
                &default_super_root_proof(),
            )
            .unwrap_err();
        match err {
            Error::UnexpectedFaultDisputeGameProof { .. } => {}
            _ => panic!("Unexpected error, got: {:?}", err),
        }
    }

    #[test]
    fn test_verify_resolved_status_invalid_game_account() {
        let mut model = default_fault_dispute_game_proof();
        model.fault_dispute_game_account.account_proof = vec![];

        let err = model
            .verify_resolved_status(
                &FaultDisputeGameConfig::default(),
                &default_super_root_proof(),
            )
            .unwrap_err();
        match err {
            Error::EthLightClientTypesError(EthLightClientTypesError::MptVerification {
                ..
            }) => {}
            _ => panic!("Unexpected error, got: {:?}", err),
        }
    }

    #[test]
    fn test_verify_game_created_success() {
        let model = default_fault_dispute_game_proof();
        model
            .verify_game_created(
                &FaultDisputeGameConfig::default(),
                &default_super_root_proof(),
                DEFAULT_GAME_CREATED_AT,
            )
            .unwrap()
    }

    #[test]
    fn test_verify_game_created_error() {
        let model = default_fault_dispute_game_proof();
        let err = model
            .verify_game_created(
                &FaultDisputeGameConfig::default(),
                &default_super_root_proof(),
                DEFAULT_GAME_CREATED_AT - 1,
            )
            .unwrap_err();
        match err {
            Error::UnexpectedGameCreatedAt { .. } => {}
            _ => panic!("Unexpected error, got: {:?}", err),
        }
    }

    #[test]
    fn test_output_root_with_message_passer_success() {
        // op-sepolia
        let account = AccountUpdateInfo {
            account_proof: vec![
                hex!("f90211a0fedfd67eb63d2d5d81361cd0efa93b8c19c38b2838e66854dc475214c88a8693a000134375175777be53b0d1af72f12bd8fa34c3dafa8bd44dd92ef936e3540e9aa0ff4a57ded01f08fde62f7c373059169ea60bb3a03217c72b8f21432f07a0259ea0c32527cf8224f51b3e77e6afbdeec3e5bb18bebf00b99ee5aa2066a2c846e1a0a01663c7d41a0d8ab245f13afdbf19519a2100b17589ded43eb528c0d5a21eb2c5a0f5bbe0f614e4391bb30390b5cfee195a2f1be56bbf53f96284b5c2f0d0ce557aa06e71b868c4808116de92d1e5650441e24fa5ec1ab307b4bfa9a86ce224c8f0aea075fb503743549641cbcfed0923b8d79f25dba6670ffc15a2e2ea20f4fe777405a0948f7c61a467181e4a4abcd54fa627a74d000a270d89497c10d91989c557327aa00606954a134a292547f114ed152c90e80d0fe431169aa31b2b4125f44c27acc5a0431a9f228ff8c81fca407432a936b14bfeb03a7d22184f8d6984d04d757d9530a0659c59af8b9133666ad5559cc2d39296f506c266be4cb25bb312d5867533f5a1a0beddc79fb8645745353c9f3c3fffb05e955a27f8104066952a55284624cc863fa0ec7d1e36b540a1cac24175a0cb9799bf334b278091a97f73b030eddc2b5b33e7a0fe2a532a0b1818083e5e4c9150daeab9253906f8736a719d912d1e03b836c4d1a052037c066fb5a794a9c7f9830594d59de36880414d46b9cbed831e6842cc652480").into(),
                hex!("f90211a08db9bcd64b6153797290b23cb6bbd1299f485bdde3d76ad33f695c1075c43950a0fd395c56d8c35e215e05b63e1e3fe1dab26e638992c1667b35465f9fae64ceb3a01c6bdaa1f02aebd9a0907ca2a9cd097b3419cd7e030f49240fe3755fcaedc7eaa0ddde23a2eeea98adf8767903f920f19eaf99ffe8f51cd09e2a6b03bbd743bc8ca01df1919ccafaa6e2b0ce64c6fb82acb76e129fd837874f1db1bb4889d12eb84aa0b1973fbeb518540caf89538a6a03f1c1f0c16bd1e3d72383c10a19ea11a543cfa005d8b0b296111bada8a6a27cf10a63cb7fe329cf0a61195451e0fc5322db6e3da04a6e33ce0093cbe0cc571f49fb0f0c5a1991b81807b20a47ae3b7bd6a3f3264ca013f146bc1697c279d014c61e2ce8f7588f0078e1588a51114d67d20459ad3644a04b579879faa16e0709cb3bd072b35d82321fdb6f7b948cd4e85cfcfbe2fd114ea0865d212791df9e0572301bb291f3590bdc58d0775084bd2e8ede9a9b0d2e540ca067eb5fa3bbb5fb1042176f18a595918917bb55e9b6e76e312aab3a9475cef130a06f3d1ad50fd8760f4b3d3c958091686503902dba318a3346bda90b58d8ec9384a0dfdc20fc7809b7826a24c4e41cb39cc89081b6eb4a63c96403c386178c4f347ba024b331c177c713e464d67cb8d41ab63de1dd5c16149ceec89bcf19e7f6b9e3b9a09e0228c4ecaeacbaed895cb63c4d638090efb09c2af832724b52d7100d68608480").into(),
                hex!("f90211a08fa61dcb8ef97f20f703fff7cb8be4407d528af6a4157348066e20175bc41d66a01e86d02a1c54dab8b9e07408031dc4704a374128e71e554dada6f8c8369b0975a0e7c8f9804d218d0edb94fa67be8f11488ef77dec1ae5a0dc3fac6d5dd2654655a0e0661bac2b420c4deb9017cc87e0e4b26133d875639a268f33fb699a25974f16a0f78a552f0f452fc45dfe582e0f22f2c79a56637c40142dcd486359010956ec63a095a0f9fc67204866d5d7b4dc267f42bcd12497ea65d9dcb4cf00f511d66a7a11a0ca485d6e8c3d05abe00f9aa4e8169d5ecf2a25562243f2775c92570942af5870a08c11f65c702023a1c9acbff75f7cd03d9b6c2261a2b3d00ceb1daeaacb58a921a0e39fdfb86b9965bd31c866382f92171b7d25a81c2d821a9ddbc1c52272406430a06d4be36fca5d4c13c8eedbe4c6d5fe529be2b808a0efb4b300a03d38297fd6d3a0c1beebc914ee9d375c572daab13411be1c19a9caf77cafa7f76d13d67d9c9693a0cf98d6b3117b7e76eff304e15836e323993c66b72a704cfe36f5e113bdbf6ee6a02eb377baa5888c4ec42ff60bb9c69da078ffd34797e5d2e3de2da385e0c1b4bda00c441eec4b17ca2570ea5cb5b63e5458842531df7124206bbbb176c0280dd87ca07d065533d1f2b91ddfb19016c1a7da0c793e1c8900005521e775156ee6e76ad1a091753f8ca118be774ef123353ab410546f7c849321fbcf167ff636e8741c476280").into(),
                hex!("f90211a036d52302820cb69d5d3ae4c017f01b866a662097c29656fec117b3b9e6846da3a0c811e7a2babd507c014be29490c1526935e8f78527ec53a7657278c6f5e4e91ba0865ac766d320110909ddc53ebafa7f508a8bfcc40b3d7eb5e05daf3b296ba6bea086b68727dc684a156cbe36a77debedb767ef1bf2650196a9d95f685bd2c8b3f3a05c4db4cceda9c90714f1b6a084d284370a0302b4647aa909c2c90773be5c55d0a0b6c4afdac4b8c4aadb8bee424f907a0f2c15b5c714607285728d1f2be189056ea0542148fcb22348f09e4604396225d14cc5fb774ed99a5b8d75d563d8c1024ee1a0685c61ba219ff719f0e3592d4aaefda3ca038558d643d3ace8b99e61d03cd5baa09ce694ddf89266d5bb59ad7ca73fdbeefbe3e2eafd42a6f89df3b2447bf829cba0fa73e0efca08187d53e453f4b62739ab60a5ab48a9fe1112b1f35b007e87a00ba08d603193cdf44931e2b74724c586fe7e414ed588ce880304342fd6386b33a62ea03619820603709df22a209fa2c8f1f4abf936a3b66fa3035811fd33df1c4937caa0329fcb81a31c300d825f7802c7402f0735bd3a97b07b6a7823b39cae487f9d6ba00caaca59e8ec3c63eb6d2930c4d1e16bbfbf4534b4cb3a19b5ccff1194a37c41a0c90f5529adf6e5624d5e2c7370978f587b8ef91096875de78007c7743331af36a0a7bdf5a51e28903edc8fb069b5a6c7e504838db6da78f5e8ef37165529f4639a80").into(),
                hex!("f90211a08999d72ab9c8ec2b49a9e76353f190e77b0892131af950f1339b648c7dbb1dcda093e3cf894097a37ede81c812c809757b65e5a7e82cf943c973b52330085d3a26a016f093c63f49a7f981a2f97196f56e8a3b55b412d15935fc641f766b2f92b681a0d2c6555ab840d1d93d8b8c7e1a9cb69cc055ff38e0000a770466fc36253f76fba00b9540ed4e83c9d9a8e654b81c04cd08c099f072151b7f7625ded4c47ced579ea00f7ecf6842364141f927b51baf7542631f1a0d8154b72720bea3b3356cf653e6a07bb2291f8ed2816ca1065ea4136f8b561114fb008d8cb0025ae96c291d4b7a1ea01c96cb000805941ad012cc157ce322ca066c6049c8783588ede787b817bbac5aa0d073e886f3fc2efe07a896178aa632315403cd7e670d02727e1ea14ea5ff6b7fa03c0f988e8d13152da497fb26a28eb551b8d97663efaeeeafa6e7575c9a6d764ca0248dae2cb0ea2b3538aadaa6fd23f03657b8e1473c1bafcd3fd0615ab9d78e02a0787207b81d402a739560795a6c0298a55327ba85e0b248cb3b99f9752840db69a02de370ed5728fecb42b04f10d4b16bf39f42e8f9c1bb4d210cea38f74d2f77e9a0a902034cdb877ec394f860d5a025e1bbca491f5aebef9dfa0cde0c9bc51821ada07c83283249ac61edc125055ae1681fb30a0333259d9f37b7ad967b697ebd68eba04f877b2cc0ee9935a4956936d20311d7dc02d5be9016de3957f4b9026da006ba80").into(),
                hex!("f90171a0a36522f33aa8aa1a34809947df9743637c4d3e4157818a20d05aa11ea6aec089a08f337a6a953840302c4c769b557c079b21250f8cb9df8b30254644c5cec9b44ca08a62b3148e9b7ed5d97cf97f2a34bfffb1b348934aa5c28f7810317290f9e29ca06281f1878de04b10770ed33aa5a55a3f039ab935a1ad89bf4bc8c48e0d8ee07480a0a3b41e5ba57c21b1c6527916863bb0196b1c95cdbd6689033dd38ff21b747bab80a053ccff59dec13ee4187c0bb34292c47ad0876add114af6102a68aaaec08ed66ea09b498012f0d0b04fc192ebf58f013194908fa42d05155988d19b5eee16d6cb5880a0ed008974019ae455b30143ecb4343670a5e833077b10ac41335acdd49987979580a0dabb4f84b9c2b7cda9a21584922989c756a6be35841458a336ee8826706fab9fa0aac904afdd7ac137512ca85b2e31a571debb6870208cd77848c7eb98b68c563ea0512911f3b6e5ebb8873150482eb4af8e3912303fe61111e2a0d3e20eba03bc868080").into(),
                hex!("f87180808080808080808080a0ab443673181c2a53d61e422ac0e4e95bb78d56aa6a39909e0647bc9e0cbc0947a01fc98fe9dc0c9ab99033a76639211f18e48f69eb3e8f13c4920d3e12b6821f4ca06e96614e580b1f61c57d5d228c777c22dcafb21fefe4abd066497e63b911533e80808080").into(),
                hex!("f8709d30147f4cc0e0156d993334777d699c312c2fe454f8b3fa338ed309f4a0b850f84e028a14bedd953e2e38dbb0e6a03476605a8835d26d43b140c732ee51181df216c2d1041b6c661feda6c0c0c8a0a01f958654ab06a152993e7a0ae7b6dbb0d4b19265cc9337b8789fe1353bd9dc35").into(),
            ],
            account_storage_root: hex!("3476605a8835d26d43b140c732ee51181df216c2d1041b6c661feda6c0c0c8a0").into(),
        };
        let l2_state_root: B256 =
            hex!("b93e70c874b195a821574f96a808da20a555f312f9171d215685d7f010da5ffe").into();

        // assert equals
        let l2_head_hash: B256 =
            hex!("12348dc33fa740c5eb9d1d7ba61723ce97bff8499b52dbe402e751f46bed35df").into();

        let output_root: B256 =
            hex!("5cac0ff77cc47f04bfc4854c798d53a1ec8091297cfe8f560737865a8d386402").into();

        assert_eq!(
            HeaderWithMessagePasserAccount::compute_output_root_from_state_and_hash(
                &account,
                &l2_state_root,
                l2_head_hash
            )
            .unwrap(),
            output_root
        );
        assert_ne!(
            HeaderWithMessagePasserAccount::compute_output_root_from_state_and_hash(
                &account,
                &l2_state_root,
                B256::from([0u8; 32])
            )
            .unwrap(),
            output_root
        );
    }

    #[test]
    fn test_trusted_to_resolved_l2_success() {
        // op-sepolia
        let raw : Vec<Vec<u8>>= vec![
            hex!("f9026ca02b1328386eafe47f7ee204efbe56d2e4e887f0c6ec3c8af09d3645e1a2f047ada01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347944200000000000000000000000000000000000011a0449a87a92b6e564947325c980fab3c0402e8469bd65d585460a8f6f90ec1c76fa06b14d5021010a6af0b06e259cfd57bd0c6259e5c1fccc3014c8fd5afcba2d09da01a93eebc5b6ec6993b78e6e4101fe334f738c6fd11e18b5b777590c17461325bb90100080085040000005e18000009002000005000008400100100000001000000000400080008462041002200010101002800a40210004040100400400e04018620000900700000040220800028201002220000c00000810440000108001002832009480401c0020802488600200000022800002800002040003200010080010200008000404080000020220820080000001004002a00100488902010100004400003010900028000010000500000000300400000000100e402000005420028000100000281220c00084000295400000000100100000c0804100000000100000060901060040100100e0040000000002088211a8000100001080801210001a0081000808401b67a3d8402625a0083fb8334846843d0268900000000fa00000002a0c704ae5ae3caf7cd72682fc2527737863b5ded45bf4118223d9fc12238bc383188000000000000000081fca0fd86ea0f27301509e13b73ad83c33f8eb14cdb93d8ee68a1b373ae709c1f50b38080a0a97030baf503d279e7910eb1ef2990e619066be4eeb7690e1d07f4b7594b44f8a0e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855").into(),
            hex!("f9026ca064d6ef43aff2656a35f6bf515b7ab6e243cefc7a1d302e6d77332429356cea00a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347944200000000000000000000000000000000000011a023b66d8fb95d4a1c61eb9ad6525d6680bbfe8b166be10f792b948e556966a140a0258b0aec4fbaed124c47e49ad0fe7748bb10a2d05417251b27bb911bb0981c9da03d7fc3ef97539e4b9e8aa97549020142b63ce9c024684973039ad85215147dbfb901000000000000000000000000000000000000000200000000000002080000000000002000000000000000040200000000004000000800000080000000000000100000000000000040000000000004000000c0000080000000000000000040000000000000a0000000080000000000000000000010000040102000004800008200200000000000000000000000000000000000000000000004000010000800000000042000000000020000000000000000020000000000000000000800080000000805000000000000800020000000000000000010020000000400000000000000140000008000000000000000010000000000000008000000000000480000080000808401b67a3c8402625a00833dc508846843d0248900000000fa00000002a0c704ae5ae3caf7cd72682fc2527737863b5ded45bf4118223d9fc12238bc383188000000000000000081fca0fd86ea0f27301509e13b73ad83c33f8eb14cdb93d8ee68a1b373ae709c1f50b38080a0a97030baf503d279e7910eb1ef2990e619066be4eeb7690e1d07f4b7594b44f8a0e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855").into(),
            hex!("f9026ca0d22905babc8a1ca58a043275f7ec1d3c4d493039708ea33d01c936d941f06e17a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347944200000000000000000000000000000000000011a0ccf81b3184dfe952445712d537eab79191fc23f9e7ff726c1c02ba1277b3b67ca06d98916b8e9e7b4ed1b910f023bcbfb2259ec02ad718f116244a05966ad15adfa08bd4c17587b01e0c786d698e82c00185e9d27f9b4b7c6f795e792fd8e704b1a6b9010000000000000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000010800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000100000000002000000000008000000000000000000000000001080000000000000000000000000000000000000000000000000000000800000000000000000000000808401b67a3b8402625a008301f954846843d0228900000000fa00000002a0c704ae5ae3caf7cd72682fc2527737863b5ded45bf4118223d9fc12238bc383188000000000000000081fda0fd86ea0f27301509e13b73ad83c33f8eb14cdb93d8ee68a1b373ae709c1f50b38080a0a97030baf503d279e7910eb1ef2990e619066be4eeb7690e1d07f4b7594b44f8a0e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855").into(),
            hex!("f9026ca05546dbe5875ae833e4c9c8f029c2747b126d51b19b5c83b1010bedf9b77d4863a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347944200000000000000000000000000000000000011a02589d2569276ac1303c0f8b12318cbb98b996dba72670408cae7b6a677dff907a05de046fdc01219cf4ed28f11dcc657786c457a09380a359075cca4e658bebc72a0d911f1ee89cd7ef2bd358b4c90bdbc32cef9cde7319511fb5b9ce5e54fe1c7fdb90100200000001040000810000009008200a00000a0040000010a000000000000000000000018642000000000020101000020100010002200400400400002010200000010a0000004000880000000040000010048000000000002000001000000400800000000000000400000020000020000240020000040102200004180000000010000000040090080000000084000000004302000000004000000020000408001010000080000000000000800010000041000000200a00008082120002008c009000001000400080000280000400000000100000c0000180404002100000000003000008000000400000000000020080110000200000000000809400020881000808401b67a3a8402625a0083e1e44d846843d0208900000000fa00000002a03b5a04da482638753efd381eaedb86a9dc82cbc39df7ef1c254c0b0965ba656288000000000000000081fda0fd86ea0f27301509e13b73ad83c33f8eb14cdb93d8ee68a1b373ae709c1f50b38080a0b52d08a836e4012986356f3c52987f722bce832f36b232f4269479a48625bacea0e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855").into(),
            hex!("f9026ca02ac115bfee7ff22c4fef13efc0a409d27bc255ca0c647ee5b9f132bd30835144a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347944200000000000000000000000000000000000011a052a10ab552369ce633f39ef164ec99ab658b8497d677097b88fd90b72d8b202ea08fcf86a0f44edb17db007efaaf03389fb740826ee666bb29ea589f9d4ad4c431a0f6f262593287d0412b404c3563a541c58990b1411d0fd86d3213985c16f2bff3b901000000800080008800200004000000404000000000000000000002000000000000082000011000010008840000000010004400000001040000000080000080040000008000000000080000000004000000c040000800000000000000000000200080000080000800080000000000000080000800020040102000004000038200200400000400002000024200400000020000000000000004000010000040000002002000a00000020000000000010000101200020000020000000800080008000801010000000000400022040001000002000010400000000410000000002000100040000000000000000000010008004000000008010000000000410080080000808401b67a398402625a008329d71c846843d01e8900000000fa00000002a03b5a04da482638753efd381eaedb86a9dc82cbc39df7ef1c254c0b0965ba656288000000000000000081fda0fd86ea0f27301509e13b73ad83c33f8eb14cdb93d8ee68a1b373ae709c1f50b38080a0b52d08a836e4012986356f3c52987f722bce832f36b232f4269479a48625bacea0e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855").into(),
            hex!("f9026ca09ea416d1c8dae31ab0b86ffe7708f0a85fd6ed237cc925974ec8abc83b686236a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347944200000000000000000000000000000000000011a0e6d2e33d9c77c0876135258770dab795bae3c3577fb173be285d688091d82587a026d5d44401405b3ddf55aea22d60d9924cb4b399af05a49b6394023101e32a26a0eba40c4ad0804f395cd192aeb099631b3133340c4473bc33f4354488318ed2a6b9010000000000000120400000000100000000000018000010021000000000200000000000040000000000000200000080000000000008000040000000000008001000000000000000000000000158040000000000000000000000000000001000000000004000000000000000000000000000000000000010102008204010000000000000000000000000000002000000000800000000000021000000000000000000000022000004000000000040000000000000080040000200000080400000000800000002000000000020050000000000020010000060000400001000002000000010000002000000000000000000000800000000000000000000400100080002808401b67a388402625a0083090770846843d01c8900000000fa00000002a03b5a04da482638753efd381eaedb86a9dc82cbc39df7ef1c254c0b0965ba656288000000000000000081fda0fd86ea0f27301509e13b73ad83c33f8eb14cdb93d8ee68a1b373ae709c1f50b38080a0b52d08a836e4012986356f3c52987f722bce832f36b232f4269479a48625bacea0e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855").into(),
            hex!("f9026ca071d40d2cfc163ad47e8f1c151e012ad8029bc8d30c3cee5d2ee2e84a652ba286a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347944200000000000000000000000000000000000011a0bbb1530705be1e503a2ac16837913f1fa690504fa934c939b29926bccbc16cd5a0d2be13bda2cd91c689ce718637887f8194c719f9a519482a2c36c621d1c133e4a0023102c6b3a485df786c9f774063dab6b3ada87ac9c97c93dd4ffd8bb8c23712b901002c0100141040000290400040049000801000e28000000008290000000000000002004018643002000000820101182000100830000600a0040070000201060000001030000004000880002818100000010002100080040002000001001083008008000001880000008000000000040000200020c0400000020080111a040a822100800000020108000100010000000410084009440404000000801200400000008000000040004104200001000102000c0800000110808068002103300408460010021002000000200402401040000080012000008818000800008100000040223200008200020a00000000000020040000000200008000040008000103800010808401b67a378402625a0083f3ed8c846843d01a8900000000fa00000002a03b5a04da482638753efd381eaedb86a9dc82cbc39df7ef1c254c0b0965ba656288000000000000000081fda0fd86ea0f27301509e13b73ad83c33f8eb14cdb93d8ee68a1b373ae709c1f50b38080a0b52d08a836e4012986356f3c52987f722bce832f36b232f4269479a48625bacea0e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855").into(),
            hex!("f9026ca035cd344f33c0278e0b32a624f3be400f2b80aaf99474eb670e47dbdcd4a06aefa01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347944200000000000000000000000000000000000011a048d7efa05230cf0060b98484effd5a1f598f140b6f66cd75f6c652adf12216b9a0863990cf03254334c662d1fb0acb251ccb824e43cbbb3add8757de7ab4f7e9bfa06962fab6be6b3223e92558162ad39bcccbbbb11aeb80d5abf4ff94d7007694bdb901000000000000000000000000000000000000000000000000000102000000000000082000000000000000040000000000004000000800000000000000000000000020000000000000100000000000000000c000000000000000000000004000000000000000000000000000000000000000000000000040000000000000008200000000000000000000000000000000000000000000000004000000000000004000000000000000020000000000000000000000000000000000000800080008000001000000000200000000000001000000000010000000000000000100000000100000000000000000000000010000000000000008000000000000000000200000808401b67a368402625a00830698d2846843d0188900000000fa00000002a03b5a04da482638753efd381eaedb86a9dc82cbc39df7ef1c254c0b0965ba656288000000000000000081fda0fd86ea0f27301509e13b73ad83c33f8eb14cdb93d8ee68a1b373ae709c1f50b38080a0b52d08a836e4012986356f3c52987f722bce832f36b232f4269479a48625bacea0e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855").into(),
            hex!("f9026ca0ded151a77694f01764db79b1335bea46c512f19f8c5f5cf086d99a91bb009cc6a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347944200000000000000000000000000000000000011a0d09fdc694eeec6651aebf38b17422939f6c89436568ab66a0750864e0b3d5acda02f4dc899811a07b0e45ab8893ea23ff3c8f913e96d7b17ef4ecbaac0288a6befa04bf266c0174dba85ad050a9158f857612df1ab5ebe223b78bfb711cda456adefb9010008000000000000001040000000000000000000000000000000020040000000008000000000000000000400000000000000000000000000000000000002040000000000000000400000000008040000008000000000440000000002000000000000000800020000080000000000000800000000000040102000004810008000200000000000200000000000000000000000000004000200000000000000000000002000000000000000000000000000000000000000000000000810000000000800000002000000000020000000000000000000020000000400000000000060000000000000000800400000000000000000000000000000000000400000080000808401b67a358402625a0083202b68846843d0168900000000fa00000002a03b5a04da482638753efd381eaedb86a9dc82cbc39df7ef1c254c0b0965ba656288000000000000000081fda0fd86ea0f27301509e13b73ad83c33f8eb14cdb93d8ee68a1b373ae709c1f50b38080a0b52d08a836e4012986356f3c52987f722bce832f36b232f4269479a48625bacea0e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855").into(),
            hex!("f9026ca0f3f8c94178667d3a5daa1d14df3d178140e60bef3ab4a59da107f8492489e78fa01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347944200000000000000000000000000000000000011a0c0f7f14c1b0d1af04f2a5a39dd54ff3544bba4bfe18f54e6c87be116f6a8c676a06a2e9831e63915133efafd1fe5b47c28797d58d475c2ebe7a45b69ff9a340ca1a0c7a493947485a43033edcfa8736b0eddf806adb7248b45b8a5273b084e1746d2b901002800000018000000900000090082020010002080000000080005000080001000010000184430000000240201010000003000201000000004004000000106900000100000100400080000000000000081000000000004000200000000020200080800000000000000000040000022040020002000404000020000014a0400022100000000028108000400300000001500000001000004000000001600020011009000000040205000200000000180005c000a000500008040002003120400020100001102000000200c04001048000010030000088800000000100000000040003000008200000a10100000000021000000000020002000000008010100800000808401b67a348402625a0083e45ac9846843d0148900000000fa00000002a0bdc6c6d4c6b093c8d03c43d3d4b1b3583a61afc79ae21c26c0c03b049b62782688000000000000000081fda0fd86ea0f27301509e13b73ad83c33f8eb14cdb93d8ee68a1b373ae709c1f50b38080a072fdb3daec9a0a6dda140967c9d7f5c1c49acba14c0199d1681f643e23834e9fa0e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855").into(),
        ];

        let mut rlp = raw.first().unwrap().as_slice();
        let trusted = Header::decode(&mut rlp).unwrap();

        let mut rlp = raw.last().unwrap().as_slice();
        let resolved = Header::decode(&mut rlp).unwrap();

        let model = L2HeaderHistory::new(
            raw,
            AccountUpdateInfo::default(),
            AccountUpdateInfo::default(),
        )
        .unwrap();
        assert_eq!(model.first.header, trusted);
        assert_eq!(model.last.header, resolved);
    }

    #[test]
    fn test_trusted_to_resolved_l2_error() {
        // op-sepolia
        let raw : Vec<Vec<u8>>= vec![
            hex!("f9026ca02b1328386eafe47f7ee204efbe56d2e4e887f0c6ec3c8af09d3645e1a2f047ada01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347944200000000000000000000000000000000000011a0449a87a92b6e564947325c980fab3c0402e8469bd65d585460a8f6f90ec1c76fa06b14d5021010a6af0b06e259cfd57bd0c6259e5c1fccc3014c8fd5afcba2d09da01a93eebc5b6ec6993b78e6e4101fe334f738c6fd11e18b5b777590c17461325bb90100080085040000005e18000009002000005000008400100100000001000000000400080008462041002200010101002800a40210004040100400400e04018620000900700000040220800028201002220000c00000810440000108001002832009480401c0020802488600200000022800002800002040003200010080010200008000404080000020220820080000001004002a00100488902010100004400003010900028000010000500000000300400000000100e402000005420028000100000281220c00084000295400000000100100000c0804100000000100000060901060040100100e0040000000002088211a8000100001080801210001a0081000808401b67a3d8402625a0083fb8334846843d0268900000000fa00000002a0c704ae5ae3caf7cd72682fc2527737863b5ded45bf4118223d9fc12238bc383188000000000000000081fca0fd86ea0f27301509e13b73ad83c33f8eb14cdb93d8ee68a1b373ae709c1f50b38080a0a97030baf503d279e7910eb1ef2990e619066be4eeb7690e1d07f4b7594b44f8a0e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855").into(),
            hex!("f9026ca0f3f8c94178667d3a5daa1d14df3d178140e60bef3ab4a59da107f8492489e78fa01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347944200000000000000000000000000000000000011a0c0f7f14c1b0d1af04f2a5a39dd54ff3544bba4bfe18f54e6c87be116f6a8c676a06a2e9831e63915133efafd1fe5b47c28797d58d475c2ebe7a45b69ff9a340ca1a0c7a493947485a43033edcfa8736b0eddf806adb7248b45b8a5273b084e1746d2b901002800000018000000900000090082020010002080000000080005000080001000010000184430000000240201010000003000201000000004004000000106900000100000100400080000000000000081000000000004000200000000020200080800000000000000000040000022040020002000404000020000014a0400022100000000028108000400300000001500000001000004000000001600020011009000000040205000200000000180005c000a000500008040002003120400020100001102000000200c04001048000010030000088800000000100000000040003000008200000a10100000000021000000000020002000000008010100800000808401b67a348402625a0083e45ac9846843d0148900000000fa00000002a0bdc6c6d4c6b093c8d03c43d3d4b1b3583a61afc79ae21c26c0c03b049b62782688000000000000000081fda0fd86ea0f27301509e13b73ad83c33f8eb14cdb93d8ee68a1b373ae709c1f50b38080a072fdb3daec9a0a6dda140967c9d7f5c1c49acba14c0199d1681f643e23834e9fa0e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855").into(),
        ];
        let err = L2HeaderHistory::new(
            raw,
            AccountUpdateInfo::default(),
            AccountUpdateInfo::default(),
        )
        .unwrap_err();
        match err {
            Error::UnexpectedHeaderRelation { .. } => {}
            _ => panic!("Unexpected error, got: {:?}", err),
        }
    }

    #[test]
    fn test_try_from_l2_misbehaviour_error() {
        let base = RawL2Misbehaviour {
            client_id: "client_id".to_string(),
            trusted_height: Some(Height {
                revision_number: 0,
                revision_height: 1,
            }),
            super_root_proof: default_super_root_proof().as_bytes().to_vec(),
            fault_dispute_game_proof: Some(RawFaultDisputeGameProof {
                state_root: [0u8; 32].into(),
                dispute_game_factory_account: Some(RawAccountUpdate {
                    account_proof: EMPTY_LIST_RLP.into(),
                    account_storage_root: [0u8; 32].into(),
                }),
                dispute_game_factory_game_id_proof: EMPTY_LIST_RLP.into(),
                fault_dispute_game_account: Some(RawAccountUpdate {
                    account_proof: EMPTY_LIST_RLP.into(),
                    account_storage_root: [0u8; 32].into(),
                }),
                fault_dispute_game_game_status_proof: EMPTY_LIST_RLP.into(),
                fault_dispute_game_source_game_type: 0,
            }),
            latest_l1_header: Some(L1Header {
                trusted_sync_committee: Some(TrustedSyncCommittee {
                    trusted_height: Some(Height {
                        revision_number: 0,
                        revision_height: 0,
                    }),
                    sync_committee: Some(SyncCommittee {
                        pubkeys: vec![vec![0u8; 48]],
                        aggregate_pubkey: [0u8; 48].into(),
                    }),
                    is_next: false,
                }),
                consensus_update: Some(ConsensusUpdate {
                    attested_header: Some(BeaconBlockHeader {
                        slot: 0,
                        proposer_index: 0,
                        parent_root: [0u8; 32].into(),
                        state_root: [0u8; 32].into(),
                        body_root: [0u8; 32].into(),
                    }),
                    next_sync_committee: Some(SyncCommittee {
                        pubkeys: vec![vec![0u8; 48]],
                        aggregate_pubkey: [0u8; 48].into(),
                    }),
                    next_sync_committee_branch: vec![vec![0u8; 32]],
                    finalized_header: Some(BeaconBlockHeader {
                        slot: 0,
                        proposer_index: 0,
                        parent_root: [0u8; 32].into(),
                        state_root: [0u8; 32].into(),
                        body_root: [0u8; 32].into(),
                    }),
                    finalized_header_branch: vec![],
                    finalized_execution_root: [0u8; 32].into(),
                    finalized_execution_branch: vec![],
                    sync_aggregate: Some(SyncAggregate {
                        sync_committee_bits: [0u8; 4].into(),
                        sync_committee_signature: [0u8; 96].into(),
                    }),
                    signature_slot: 0,
                }),
                execution_update: Some(ExecutionUpdate {
                    state_root: [0u8; 32].into(),
                    state_root_branch: vec![],
                    block_number: 0,
                    block_number_branch: vec![],
                    rlp: vec![],
                    block_hash: [0u8; 32].into(),
                    block_hash_branch: vec![],
                }),
            }),
            first_l2_to_l1_message_passer_account: Some(RawAccountUpdate {
                account_proof: EMPTY_LIST_RLP.into(),
                account_storage_root: [0u8; 32].into(),
            }),
            last_l2_to_l1_message_passer_account: Some(RawAccountUpdate {
                account_proof: EMPTY_LIST_RLP.into(),
                account_storage_root: [0u8; 32].into(),
            }),
            l2_header_history: vec![],
            submitted_l1_proof: None,
            l1_header_history: vec![],
        };

        // Common
        let mut raw = base.clone();
        raw.latest_l1_header
            .as_mut()
            .unwrap()
            .execution_update
            .as_mut()
            .unwrap()
            .state_root = [1u8; 32].into();
        let err = L2Misbehaviour::<32>::try_from(raw).unwrap_err();
        match err {
            Error::UnexpectedL1HeaderStateRoot(_, _) => {}
            _ => panic!("Unexpected error, got: {:?}", err),
        }

        //
        // future
        //

        // no header found
        let mut raw = base.clone();
        raw.submitted_l1_proof = raw.fault_dispute_game_proof.clone();
        let err = L2Misbehaviour::<32>::try_from(raw).unwrap_err();
        match err {
            Error::NoHeaderFound => {}
            _ => panic!("Unexpected error, got: {:?}", err),
        }

        // history mismatch (number)
        let mut raw = base.clone();
        raw.submitted_l1_proof = raw.fault_dispute_game_proof.clone();
        raw.l1_header_history = vec![
            hex!("f9026ca02b1328386eafe47f7ee204efbe56d2e4e887f0c6ec3c8af09d3645e1a2f047ada01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347944200000000000000000000000000000000000011a0449a87a92b6e564947325c980fab3c0402e8469bd65d585460a8f6f90ec1c76fa06b14d5021010a6af0b06e259cfd57bd0c6259e5c1fccc3014c8fd5afcba2d09da01a93eebc5b6ec6993b78e6e4101fe334f738c6fd11e18b5b777590c17461325bb90100080085040000005e18000009002000005000008400100100000001000000000400080008462041002200010101002800a40210004040100400400e04018620000900700000040220800028201002220000c00000810440000108001002832009480401c0020802488600200000022800002800002040003200010080010200008000404080000020220820080000001004002a00100488902010100004400003010900028000010000500000000300400000000100e402000005420028000100000281220c00084000295400000000100100000c0804100000000100000060901060040100100e0040000000002088211a8000100001080801210001a0081000808401b67a3d8402625a0083fb8334846843d0268900000000fa00000002a0c704ae5ae3caf7cd72682fc2527737863b5ded45bf4118223d9fc12238bc383188000000000000000081fca0fd86ea0f27301509e13b73ad83c33f8eb14cdb93d8ee68a1b373ae709c1f50b38080a0a97030baf503d279e7910eb1ef2990e619066be4eeb7690e1d07f4b7594b44f8a0e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855").into(),
            hex!("f9026ca064d6ef43aff2656a35f6bf515b7ab6e243cefc7a1d302e6d77332429356cea00a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347944200000000000000000000000000000000000011a023b66d8fb95d4a1c61eb9ad6525d6680bbfe8b166be10f792b948e556966a140a0258b0aec4fbaed124c47e49ad0fe7748bb10a2d05417251b27bb911bb0981c9da03d7fc3ef97539e4b9e8aa97549020142b63ce9c024684973039ad85215147dbfb901000000000000000000000000000000000000000200000000000002080000000000002000000000000000040200000000004000000800000080000000000000100000000000000040000000000004000000c0000080000000000000000040000000000000a0000000080000000000000000000010000040102000004800008200200000000000000000000000000000000000000000000004000010000800000000042000000000020000000000000000020000000000000000000800080000000805000000000000800020000000000000000010020000000400000000000000140000008000000000000000010000000000000008000000000000480000080000808401b67a3c8402625a00833dc508846843d0248900000000fa00000002a0c704ae5ae3caf7cd72682fc2527737863b5ded45bf4118223d9fc12238bc383188000000000000000081fca0fd86ea0f27301509e13b73ad83c33f8eb14cdb93d8ee68a1b373ae709c1f50b38080a0a97030baf503d279e7910eb1ef2990e619066be4eeb7690e1d07f4b7594b44f8a0e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855").into(),
        ];
        let err = L2Misbehaviour::<32>::try_from(raw).unwrap_err();
        match err {
            Error::UnexpectedL1HeaderNumber(_, _) => {}
            _ => panic!("Unexpected error, got: {:?}", err),
        }

        // history mismatch (state root)
        let mut raw = base.clone();
        raw.submitted_l1_proof = raw.fault_dispute_game_proof.clone();
        raw.l1_header_history = vec![
            hex!("f9026ca02b1328386eafe47f7ee204efbe56d2e4e887f0c6ec3c8af09d3645e1a2f047ada01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347944200000000000000000000000000000000000011a0449a87a92b6e564947325c980fab3c0402e8469bd65d585460a8f6f90ec1c76fa06b14d5021010a6af0b06e259cfd57bd0c6259e5c1fccc3014c8fd5afcba2d09da01a93eebc5b6ec6993b78e6e4101fe334f738c6fd11e18b5b777590c17461325bb90100080085040000005e18000009002000005000008400100100000001000000000400080008462041002200010101002800a40210004040100400400e04018620000900700000040220800028201002220000c00000810440000108001002832009480401c0020802488600200000022800002800002040003200010080010200008000404080000020220820080000001004002a00100488902010100004400003010900028000010000500000000300400000000100e402000005420028000100000281220c00084000295400000000100100000c0804100000000100000060901060040100100e0040000000002088211a8000100001080801210001a0081000808401b67a3d8402625a0083fb8334846843d0268900000000fa00000002a0c704ae5ae3caf7cd72682fc2527737863b5ded45bf4118223d9fc12238bc383188000000000000000081fca0fd86ea0f27301509e13b73ad83c33f8eb14cdb93d8ee68a1b373ae709c1f50b38080a0a97030baf503d279e7910eb1ef2990e619066be4eeb7690e1d07f4b7594b44f8a0e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855").into(),
            hex!("f9026ca064d6ef43aff2656a35f6bf515b7ab6e243cefc7a1d302e6d77332429356cea00a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347944200000000000000000000000000000000000011a023b66d8fb95d4a1c61eb9ad6525d6680bbfe8b166be10f792b948e556966a140a0258b0aec4fbaed124c47e49ad0fe7748bb10a2d05417251b27bb911bb0981c9da03d7fc3ef97539e4b9e8aa97549020142b63ce9c024684973039ad85215147dbfb901000000000000000000000000000000000000000200000000000002080000000000002000000000000000040200000000004000000800000080000000000000100000000000000040000000000004000000c0000080000000000000000040000000000000a0000000080000000000000000000010000040102000004800008200200000000000000000000000000000000000000000000004000010000800000000042000000000020000000000000000020000000000000000000800080000000805000000000000800020000000000000000010020000000400000000000000140000008000000000000000010000000000000008000000000000480000080000808401b67a3c8402625a00833dc508846843d0248900000000fa00000002a0c704ae5ae3caf7cd72682fc2527737863b5ded45bf4118223d9fc12238bc383188000000000000000081fca0fd86ea0f27301509e13b73ad83c33f8eb14cdb93d8ee68a1b373ae709c1f50b38080a0a97030baf503d279e7910eb1ef2990e619066be4eeb7690e1d07f4b7594b44f8a0e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855").into(),
        ];
        raw.latest_l1_header
            .as_mut()
            .unwrap()
            .execution_update
            .as_mut()
            .unwrap()
            .block_number = 28736061;
        let err = L2Misbehaviour::<32>::try_from(raw).unwrap_err();
        match err {
            Error::UnexpectedSubmittedL1HeaderStateRoot(_, _) => {}
            _ => panic!("Unexpected error, got: {:?}", err),
        }

        //
        // past
        //

        // invalid resolved l2
        let mut raw = base.clone();
        raw.l2_header_history = vec![
            hex!("f9026ca02b1328386eafe47f7ee204efbe56d2e4e887f0c6ec3c8af09d3645e1a2f047ada01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347944200000000000000000000000000000000000011a0449a87a92b6e564947325c980fab3c0402e8469bd65d585460a8f6f90ec1c76fa06b14d5021010a6af0b06e259cfd57bd0c6259e5c1fccc3014c8fd5afcba2d09da01a93eebc5b6ec6993b78e6e4101fe334f738c6fd11e18b5b777590c17461325bb90100080085040000005e18000009002000005000008400100100000001000000000400080008462041002200010101002800a40210004040100400400e04018620000900700000040220800028201002220000c00000810440000108001002832009480401c0020802488600200000022800002800002040003200010080010200008000404080000020220820080000001004002a00100488902010100004400003010900028000010000500000000300400000000100e402000005420028000100000281220c00084000295400000000100100000c0804100000000100000060901060040100100e0040000000002088211a8000100001080801210001a0081000808401b67a3d8402625a0083fb8334846843d0268900000000fa00000002a0c704ae5ae3caf7cd72682fc2527737863b5ded45bf4118223d9fc12238bc383188000000000000000081fca0fd86ea0f27301509e13b73ad83c33f8eb14cdb93d8ee68a1b373ae709c1f50b38080a0a97030baf503d279e7910eb1ef2990e619066be4eeb7690e1d07f4b7594b44f8a0e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855").into(),
            hex!("f9026ca064d6ef43aff2656a35f6bf515b7ab6e243cefc7a1d302e6d77332429356cea00a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347944200000000000000000000000000000000000011a023b66d8fb95d4a1c61eb9ad6525d6680bbfe8b166be10f792b948e556966a140a0258b0aec4fbaed124c47e49ad0fe7748bb10a2d05417251b27bb911bb0981c9da03d7fc3ef97539e4b9e8aa97549020142b63ce9c024684973039ad85215147dbfb901000000000000000000000000000000000000000200000000000002080000000000002000000000000000040200000000004000000800000080000000000000100000000000000040000000000004000000c0000080000000000000000040000000000000a0000000080000000000000000000010000040102000004800008200200000000000000000000000000000000000000000000004000010000800000000042000000000020000000000000000020000000000000000000800080000000805000000000000800020000000000000000010020000000400000000000000140000008000000000000000010000000000000008000000000000480000080000808401b67a3c8402625a00833dc508846843d0248900000000fa00000002a0c704ae5ae3caf7cd72682fc2527737863b5ded45bf4118223d9fc12238bc383188000000000000000081fca0fd86ea0f27301509e13b73ad83c33f8eb14cdb93d8ee68a1b373ae709c1f50b38080a0a97030baf503d279e7910eb1ef2990e619066be4eeb7690e1d07f4b7594b44f8a0e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855").into(),
        ];
        let err = L2Misbehaviour::<32>::try_from(raw).unwrap_err();
        match err {
            Error::UnexpectedResolvedL2Timestamp(_, _) => {}
            _ => panic!("Unexpected error, got: {:?}", err),
        }

        // no l2 history
        let raw = base.clone();
        let err = L2Misbehaviour::<32>::try_from(raw).unwrap_err();
        match err {
            Error::NoHeaderFound => {}
            _ => panic!("Unexpected error, got: {:?}", err),
        }
    }
}
