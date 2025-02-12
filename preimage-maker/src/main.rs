#![feature(const_trait_impl)]
extern crate core;

use crate::host::single::cli::SingleChainHostCli;
use crate::host::single::orchestrator::DerivationRequest;
use crate::server::{start_http_server_task, DerivationState};
use clap::Parser;
use kona_client::single;
use kona_host::{DetachedHostOrchestrator, HostOrchestrator, PreimageServer};
use kona_preimage::{
    BidirectionalChannel, CommsClient, HintReader, HintWriter, OracleReader, OracleServer,
    PreimageKey,
};
use l2_client::L2Client;
use log::error;
use lru::LruCache;
use maili_genesis::RollupConfig;
use serde::Serialize;
use std::fmt::Debug;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, oneshot, RwLock};
use tokio::task;
use tracing::metadata::LevelFilter;
use tracing::{info, Level};
use tracing_subscriber::filter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

mod host;
pub mod l2_client;
mod server;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config = SingleChainHostCli::parse();

    // start tracing
    let filter = filter::EnvFilter::from_default_env()
        .add_directive("optimism_preimage_maker=info".parse()?);
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .with(filter)
        .init();
    info!("start optimism preimage-maker");

    let l2_client = L2Client::new(
        config.l2_rollup_address.to_string(),
        config.l2_node_address.to_string(),
    );
    let rollup_config = l2_client.rollup_config().await?;
    let chain_id = l2_client.chain_id().await?;

    // Start HTTP server
    let http_server_task = start_http_server_task(
        config.http_server_addr.as_str(),
        DerivationState {
            rollup_config: rollup_config.clone(),
            config: config.clone(),
            l2_chain_id: chain_id,
        },
    );

    let result = http_server_task.await;
    info!("server result : {:?}", result);

    Ok(())
}
