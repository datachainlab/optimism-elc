//! This module contains all CLI-specific code for the single chain entrypoint.

use clap::Parser;
use serde::Serialize;

/// The host binary CLI application arguments.
#[derive(Default, Parser, Serialize, Clone, Debug)]
pub struct SingleChainHostCli {
    /// Address of L2 JSON-RPC endpoint to use (eth and debug namespace required).
    #[clap(long, visible_alias = "l2", default_value = "http://localhost:9545")]
    pub l2_node_address: String,
    /// Address of L1 JSON-RPC endpoint to use (eth and debug namespace required)
    #[clap(long, visible_alias = "l1", default_value = "http://localhost:8545")]
    pub l1_node_address: String,
    /// Address of the L1 Beacon API endpoint to use.
    #[clap(
        long,
        visible_alias = "beacon",
        default_value = "http://localhost:5052"
    )]
    pub l1_beacon_address: String,
    /// Address of L2 JSON-RPC endpoint to use (eth and debug namespace required).
    #[clap(
        long,
        visible_alias = "rollup",
        default_value = "http://localhost:7545"
    )]
    pub l2_rollup_address: String,
    /// Path to rollup config. If provided, the host will use this config instead of attempting to
    /// look up the config in the superchain registry.
    #[clap(long, default_value = "0.0.0.0:10080")]
    pub http_server_addr: String,
}
