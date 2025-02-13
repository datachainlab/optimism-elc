use crate::host::single::cli::SingleChainHostCli;
use crate::host::single::orchestrator::DerivationRequest;
use alloy_primitives::B256;
use anyhow::{Context, Result};
use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::post;
use axum::Json;
use log::info;
use maili_genesis::RollupConfig;
use serde::{Deserialize, Serialize};
use std::fmt::Debug;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

pub struct DerivationState {
    pub rollup_config: RollupConfig,
    pub config: SingleChainHostCli,
    pub l2_chain_id: u64,
}

async fn start_http_server(addr: &str, derivation_state: DerivationState) -> Result<()> {
    let app = axum::Router::new()
        .route("/derivation", post(derivation))
        .with_state(Arc::new(derivation_state));

    let listener = TcpListener::bind(addr).await?;
    tracing::info!("listening on {}", addr);
    axum::serve(listener, app).await?;
    Ok(())
}

pub fn start_http_server_task(addr: &str, state: DerivationState) -> JoinHandle<Result<()>> {
    let addr = addr.to_string();
    tokio::spawn(async move {
        start_http_server(&addr, state)
            .await
            .context("http server error")
    })
}

// handler

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Request {
    pub l1_head_hash: B256,
    pub agreed_l2_head_hash: B256,
    pub agreed_l2_output_root: B256,
    pub l2_output_root: B256,
    pub l2_block_number: u64,
}

async fn derivation(
    State(state): State<Arc<DerivationState>>,
    Json(payload): Json<crate::server::Request>,
) -> (StatusCode, Vec<u8>) {
    info!("derivation request: {:?}", payload);
    let derivation = DerivationRequest {
        config: state.config.clone(),
        rollup_config: state.rollup_config.clone(),
        l2_chain_id: state.l2_chain_id,
        agreed_l2_head_hash: payload.agreed_l2_head_hash,
        agreed_l2_output_root: payload.agreed_l2_output_root,
        l1_head_hash: payload.l1_head_hash,
        l2_output_root: payload.l2_output_root,
        l2_block_number: payload.l2_block_number,
    };
    match derivation.start().await {
        Ok(preimage) => {
            info!("derivation success");
            (StatusCode::OK, preimage)
        }
        Err(e) => {
            info!("failed to run derivation: {:?}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, vec![])
        }
    }
}
