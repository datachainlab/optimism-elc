#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct L1Config {
    #[prost(bytes = "vec", tag = "1")]
    pub genesis_validators_root: ::prost::alloc::vec::Vec<u8>,
    #[prost(uint64, tag = "2")]
    pub min_sync_committee_participants: u64,
    #[prost(uint64, tag = "3")]
    pub genesis_time: u64,
    #[prost(message, optional, tag = "4")]
    pub fork_parameters: ::core::option::Option<
        super::super::ethereum::v1::ForkParameters,
    >,
    #[prost(uint64, tag = "5")]
    pub seconds_per_slot: u64,
    #[prost(uint64, tag = "6")]
    pub slots_per_epoch: u64,
    #[prost(uint64, tag = "7")]
    pub epochs_per_sync_committee_period: u64,
    #[prost(message, optional, tag = "8")]
    pub trust_level: ::core::option::Option<super::super::ethereum::v1::Fraction>,
    #[prost(message, optional, tag = "9")]
    pub trusting_period: ::core::option::Option<
        super::super::super::super::google::protobuf::Duration,
    >,
    #[prost(message, optional, tag = "10")]
    pub max_clock_drift: ::core::option::Option<
        super::super::super::super::google::protobuf::Duration,
    >,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct FaultDisputeGameConfig {
    #[prost(uint32, tag = "1")]
    pub dispute_game_factory_target_storage_slot: u32,
    #[prost(uint32, tag = "2")]
    pub fault_dispute_game_status_slot: u32,
    #[prost(uint32, tag = "3")]
    pub fault_dispute_game_status_slot_offset: u32,
    #[prost(uint32, tag = "4")]
    pub status_defender_win: u32,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ClientState {
    #[prost(uint64, tag = "1")]
    pub chain_id: u64,
    #[prost(bytes = "vec", tag = "2")]
    pub ibc_store_address: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    pub ibc_commitments_slot: ::prost::alloc::vec::Vec<u8>,
    #[prost(message, optional, tag = "4")]
    pub latest_height: ::core::option::Option<
        super::super::super::core::client::v1::Height,
    >,
    #[prost(bool, tag = "5")]
    pub frozen: bool,
    #[prost(bytes = "vec", tag = "6")]
    pub rollup_config_json: ::prost::alloc::vec::Vec<u8>,
    #[prost(message, optional, tag = "7")]
    pub l1_config: ::core::option::Option<L1Config>,
    #[prost(message, optional, tag = "8")]
    pub fault_dispute_game_config: ::core::option::Option<FaultDisputeGameConfig>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct L1Header {
    #[prost(message, optional, tag = "1")]
    pub trusted_sync_committee: ::core::option::Option<
        super::super::ethereum::v1::TrustedSyncCommittee,
    >,
    #[prost(message, optional, tag = "2")]
    pub consensus_update: ::core::option::Option<
        super::super::ethereum::v1::ConsensusUpdate,
    >,
    #[prost(message, optional, tag = "3")]
    pub execution_update: ::core::option::Option<
        super::super::ethereum::v1::ExecutionUpdate,
    >,
    #[prost(uint64, tag = "4")]
    pub timestamp: u64,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Derivation {
    #[prost(bytes = "vec", tag = "1")]
    pub agreed_l2_output_root: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub l2_output_root: ::prost::alloc::vec::Vec<u8>,
    #[prost(uint64, tag = "3")]
    pub l2_block_number: u64,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Header {
    #[prost(message, optional, tag = "1")]
    pub trusted_height: ::core::option::Option<
        super::super::super::core::client::v1::Height,
    >,
    #[prost(message, optional, tag = "2")]
    pub account_update: ::core::option::Option<AccountUpdate>,
    #[prost(message, optional, tag = "3")]
    pub derivation: ::core::option::Option<Derivation>,
    #[prost(bytes = "vec", tag = "4")]
    pub preimages: ::prost::alloc::vec::Vec<u8>,
    #[prost(message, repeated, tag = "5")]
    pub trusted_to_deterministic: ::prost::alloc::vec::Vec<L1Header>,
    #[prost(message, repeated, tag = "6")]
    pub deterministic_to_latest: ::prost::alloc::vec::Vec<L1Header>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ConsensusState {
    #[prost(bytes = "vec", tag = "1")]
    pub storage_root: ::prost::alloc::vec::Vec<u8>,
    #[prost(uint64, tag = "2")]
    pub timestamp: u64,
    #[prost(bytes = "vec", tag = "3")]
    pub output_root: ::prost::alloc::vec::Vec<u8>,
    #[prost(uint64, tag = "4")]
    pub l1_slot: u64,
    #[prost(bytes = "vec", tag = "5")]
    pub l1_current_sync_committee: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes = "vec", tag = "6")]
    pub l1_next_sync_committee: ::prost::alloc::vec::Vec<u8>,
    #[prost(uint64, tag = "7")]
    pub l1_timestamp: u64,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AccountUpdate {
    #[prost(bytes = "vec", tag = "1")]
    pub account_proof: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub account_storage_root: ::prost::alloc::vec::Vec<u8>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct FaultDisputeGameFactoryProof {
    #[prost(message, optional, tag = "1")]
    pub l1_header: ::core::option::Option<L1Header>,
    #[prost(bytes = "vec", tag = "2")]
    pub dispute_game_factory_address: ::prost::alloc::vec::Vec<u8>,
    #[prost(message, optional, tag = "3")]
    pub dispute_game_factory_account: ::core::option::Option<AccountUpdate>,
    #[prost(bytes = "vec", tag = "4")]
    pub dispute_game_factory_storage_proof: ::prost::alloc::vec::Vec<u8>,
    #[prost(message, optional, tag = "5")]
    pub fault_dispute_game_account: ::core::option::Option<AccountUpdate>,
    #[prost(bytes = "vec", tag = "6")]
    pub fault_dispute_game_storage_proof: ::prost::alloc::vec::Vec<u8>,
    #[prost(uint64, tag = "7")]
    pub fault_dispute_game_source_game_type: u64,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Misbehaviour {
    #[prost(string, tag = "1")]
    pub client_id: ::prost::alloc::string::String,
    #[prost(message, optional, tag = "2")]
    pub trusted_height: ::core::option::Option<
        super::super::super::core::client::v1::Height,
    >,
    #[prost(message, optional, tag = "3")]
    pub first_l2_to_l1_message_passer_account: ::core::option::Option<AccountUpdate>,
    #[prost(message, optional, tag = "4")]
    pub last_l2_to_l1_message_passer_account: ::core::option::Option<AccountUpdate>,
    #[prost(bytes = "vec", repeated, tag = "5")]
    pub l2_header_history: ::prost::alloc::vec::Vec<::prost::alloc::vec::Vec<u8>>,
    #[prost(bytes = "vec", tag = "6")]
    pub resolved_output_root: ::prost::alloc::vec::Vec<u8>,
    #[prost(message, optional, tag = "7")]
    pub fault_dispute_game_factory_proof: ::core::option::Option<
        FaultDisputeGameFactoryProof,
    >,
}
