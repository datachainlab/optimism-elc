use alloy_primitives::B256;
use anyhow::Result;
use maili_genesis::RollupConfig;
use reqwest::Response;
use serde_json::Value;

#[derive(Debug, Clone, serde::Deserialize)]
pub struct RpcResult<T> {
    pub jsonrpc: String,
    pub id: i64,
    pub result: T,
}

#[derive(Debug, Clone, serde::Serialize)]
struct RpcRequest {
    jsonrpc: String,
    method: String,
    params: Vec<Value>,
    id: i64,
}

impl Default for RpcRequest {
    fn default() -> Self {
        Self {
            jsonrpc: "2.0".into(),
            method: "".into(),
            params: vec![],
            id: 1,
        }
    }
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct L1Header {
    pub hash: B256,
    pub number: u64,
    #[serde(rename = "parentHash")]
    pub parent_hash: B256,
    pub timestamp: u64,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct L1Origin {
    pub hash: B256,
    pub number: u64,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct L2Header {
    pub hash: B256,
    pub number: u64,
    #[serde(rename = "parentHash")]
    pub parent_hash: B256,
    pub timestamp: u64,
    pub l1origin: L1Origin,
    #[serde(rename = "sequenceNumber")]
    pub sequence_number: u64,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct SyncStatus {
    pub current_l1: L1Header,
    pub current_l1_finalized: L1Header,
    pub head_l1: L1Header,
    pub safe_l1: L1Header,
    pub finalized_l1: L1Header,
    pub unsafe_l2: L2Header,
    pub safe_l2: L2Header,
    pub finalized_l2: L2Header,
    pub pending_safe_l2: L2Header,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct OutputRootAtBlock {
    #[serde(rename = "outputRoot")]
    pub output_root: B256,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct Block {
    pub hash: B256,
}

pub struct L2Client {
    op_node_addr: String,
    op_geth_addr: String,
}

impl Default for L2Client {
    fn default() -> Self {
        Self::new(
            "http://localhost:7545".into(),
            "http://localhost:9545".into(),
        )
    }
}

impl L2Client {
    pub fn new(op_node_addr: String, op_geth_addr: String) -> Self {
        Self {
            op_node_addr,
            op_geth_addr,
        }
    }

    pub async fn chain_id(&self) -> Result<u64> {
        let client = reqwest::Client::new();
        let body = RpcRequest {
            method: "eth_chainId".into(),
            ..Default::default()
        };
        let response = client
            .post(&self.op_geth_addr)
            .header("Content-Type", "application/json")
            .json(&body)
            .send()
            .await?;
        let response = self.check_response(response).await?;
        let result: RpcResult<String> = response.json().await?;
        Ok(u64::from_str_radix(&result.result[2..], 16)?)
    }

    pub async fn rollup_config(&self) -> Result<RollupConfig> {
        let client = reqwest::Client::new();
        let body = RpcRequest {
            method: "optimism_rollupConfig".into(),
            ..Default::default()
        };
        let response = client
            .post(&self.op_node_addr)
            .header("Content-Type", "application/json")
            .json(&body)
            .send()
            .await?;
        let response = self.check_response(response).await?;
        let result: RpcResult<RollupConfig> = response.json().await?;
        Ok(result.result)
    }
    pub async fn sync_status(&self) -> Result<SyncStatus> {
        let client = reqwest::Client::new();
        let body = RpcRequest {
            method: "optimism_syncStatus".into(),
            ..Default::default()
        };
        let response = client
            .post(&self.op_node_addr)
            .header("Content-Type", "application/json")
            .json(&body)
            .send()
            .await?;
        let response = self.check_response(response).await?;
        let result: RpcResult<SyncStatus> = response.json().await?;
        Ok(result.result)
    }

    pub async fn output_root_at(&self, number: u64) -> Result<B256> {
        let client = reqwest::Client::new();
        let body = RpcRequest {
            method: "optimism_outputAtBlock".into(),
            params: vec![format!("0x{:X}", number).into()],
            ..Default::default()
        };
        let response = client
            .post(&self.op_node_addr)
            .header("Content-Type", "application/json")
            .json(&body)
            .send()
            .await?;
        let response = self.check_response(response).await?;
        let result: RpcResult<OutputRootAtBlock> = response.json().await?;
        Ok(result.result.output_root)
    }

    pub async fn get_block_by_number(&self, number: u64) -> Result<Block> {
        let client = reqwest::Client::new();
        let body = RpcRequest {
            method: "eth_getBlockByNumber".into(),
            params: vec![format!("0x{:X}", number).into(), false.into()],
            ..Default::default()
        };
        let response = client
            .post(&self.op_geth_addr)
            .header("Content-Type", "application/json")
            .json(&body)
            .send()
            .await?;
        let response = self.check_response(response).await?;
        let result: RpcResult<Block> = response.json().await?;
        Ok(result.result)
    }

    async fn check_response(&self, response: Response) -> Result<Response> {
        if response.status().is_success() {
            Ok(response)
        } else {
            Err(anyhow::anyhow!(
                "Request failed with status: {} body={:?}",
                response.status(),
                response.text().await
            ))
        }
    }
}

#[cfg(test)]
mod test {
    use crate::derivation::client::l2::L2Client;

    #[tokio::test]
    pub async fn test_sync_status() {
        let client = L2Client::default();
        let result = client.sync_status().await.unwrap();
        println!("{:?}", result);
    }
}
