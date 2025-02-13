//! [SingleChainHostCli]'s [HostOrchestrator] + [DetachedHostOrchestrator] implementations.

use crate::host::single::cli::SingleChainHostCli;
use crate::host::single::fetcher::SingleChainFetcher;
use crate::host::single::local_kv::LocalKeyValueStore;
use crate::host::single::trace::{encode_to_bytes, TracingKeyValueStore};
use alloy_primitives::B256;
use alloy_provider::ReqwestProvider;
use alloy_rpc_client::RpcClient;
use alloy_transport_http::Http;
use anyhow::Result;
use kona_host::{
    Fetcher, HostOrchestrator, MemoryKeyValueStore, PreimageServer, SharedKeyValueStore,
    SplitKeyValueStore,
};
use kona_preimage::{
    BidirectionalChannel, HintReader, HintWriter, NativeChannel, OracleReader, OracleServer,
};
use kona_providers_alloy::{OnlineBeaconClient, OnlineBlobProvider};
use maili_genesis::RollupConfig;
use reqwest::Client;
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::task;

#[derive(Debug, Clone)]
pub struct DerivationRequest {
    pub config: SingleChainHostCli,
    pub rollup_config: RollupConfig,
    pub l2_chain_id: u64,
    /// for L2 derivation
    pub agreed_l2_head_hash: B256,
    pub agreed_l2_output_root: B256,
    pub l1_head_hash: B256,
    pub l2_output_root: B256,
    pub l2_block_number: u64,
}

/// The providers required for the single chain host.
#[derive(Debug)]
pub struct SingleChainProviders {
    /// The L1 EL provider.
    l1_provider: ReqwestProvider,
    /// The L1 beacon node provider.
    blob_provider: OnlineBlobProvider<OnlineBeaconClient>,
    /// The L2 EL provider.
    l2_provider: ReqwestProvider,
}

impl DerivationRequest {
    async fn create_providers(&self) -> Result<Option<SingleChainProviders>> {
        let l1_provider = http_provider(self.config.l1_node_address.as_ref());
        let blob_provider = OnlineBlobProvider::init(OnlineBeaconClient::new_http(
            self.config.l1_beacon_address.clone(),
        ))
        .await;
        let l2_provider = http_provider(self.config.l2_node_address.as_str());

        Ok(Some(SingleChainProviders {
            l1_provider,
            blob_provider,
            l2_provider,
        }))
    }

    fn create_fetcher(
        &self,
        providers: Option<SingleChainProviders>,
        kv_store: SharedKeyValueStore,
    ) -> Option<Arc<RwLock<impl Fetcher + Send + Sync + 'static>>> {
        providers.map(|providers| {
            Arc::new(RwLock::new(SingleChainFetcher::new(
                kv_store,
                providers.l1_provider,
                providers.blob_provider,
                providers.l2_provider,
                self.agreed_l2_head_hash,
            )))
        })
    }

    fn create_key_value_store(&self) -> Result<Arc<RwLock<TracingKeyValueStore>>> {
        // Only memory store is traceable
        // Using disk causes insufficient blob preimages in ELC because the already stored data is not traceable
        let local_kv_store = LocalKeyValueStore::new(self.clone());
        let mem_kv_store = MemoryKeyValueStore::new();
        let split_kv_store = SplitKeyValueStore::new(local_kv_store, mem_kv_store);
        Ok(Arc::new(RwLock::new(TracingKeyValueStore::new(Box::new(
            split_kv_store,
        )))))
    }

    async fn run_client_native(
        hint_reader: HintWriter<NativeChannel>,
        oracle_reader: OracleReader<NativeChannel>,
    ) -> Result<()> {
        kona_client::single::run(oracle_reader, hint_reader, None)
            .await
            .map_err(Into::into)
    }

    pub async fn start(&self) -> Result<Vec<u8>> {
        let hint = BidirectionalChannel::new()?;
        let preimage = BidirectionalChannel::new()?;
        let kv_store = self.create_key_value_store()?;
        let providers = self.create_providers().await?;
        let fetcher = self.create_fetcher(providers, kv_store.clone());

        let server_task = task::spawn(
            PreimageServer::new(
                OracleServer::new(preimage.host),
                HintReader::new(hint.host),
                kv_store.clone(),
                fetcher,
            )
            .start(),
        );
        let client_task = task::spawn(Self::run_client_native(
            HintWriter::new(hint.client),
            OracleReader::new(preimage.client),
        ));

        let (_, client_result) = tokio::try_join!(server_task, client_task)?;
        tracing::info!("Client result: {:?}", client_result);
        let used = {
            let mut lock = kv_store.write().await;
            std::mem::take(&mut lock.used)
        };
        let preimage = encode_to_bytes(used);
        tracing::info!("Preimage size: {}", preimage.len());
        Ok(preimage)
    }
}

fn http_provider(url: &str) -> ReqwestProvider {
    let url = url.parse().unwrap();
    let http = Http::<Client>::new(url);
    ReqwestProvider::new(RpcClient::new(http, true))
}
