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
    #[prost(message, optional, tag = "5")]
    pub trusting_period: ::core::option::Option<
        super::super::super::super::google::protobuf::Duration,
    >,
    #[prost(message, optional, tag = "6")]
    pub max_clock_drift: ::core::option::Option<
        super::super::super::super::google::protobuf::Duration,
    >,
    #[prost(bool, tag = "7")]
    pub frozen: bool,
    #[prost(bytes = "vec", tag = "8")]
    pub rollup_config_json: ::prost::alloc::vec::Vec<u8>,
    #[prost(message, optional, tag = "9")]
    pub l1_config: ::core::option::Option<L1Config>,
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
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Derivation {
    #[prost(bytes = "vec", tag = "1")]
    pub agreed_l2_head_hash: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub agreed_l2_output_root: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    pub l2_output_root: ::prost::alloc::vec::Vec<u8>,
    #[prost(uint64, tag = "4")]
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
    pub account_update: ::core::option::Option<
        super::super::ethereum::v1::AccountUpdate,
    >,
    #[prost(message, optional, tag = "3")]
    pub l1_head: ::core::option::Option<L1Header>,
    #[prost(message, optional, tag = "4")]
    pub derivation: ::core::option::Option<Derivation>,
    #[prost(bytes = "vec", tag = "5")]
    pub preimages: ::prost::alloc::vec::Vec<u8>,
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
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Misbehaviour {
    #[prost(string, tag = "1")]
    pub client_id: ::prost::alloc::string::String,
    #[prost(message, optional, tag = "2")]
    pub header_1: ::core::option::Option<Header>,
    #[prost(message, optional, tag = "3")]
    pub header_2: ::core::option::Option<Header>,
}
