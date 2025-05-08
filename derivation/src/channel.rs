use kona_preimage::{Channel, PreimageKey, PreimageOracleClient};
use kona_preimage::errors::ChannelResult;
use alloc::boxed::Box;
use core::cell::UnsafeCell;
use crate::oracle::MemoryOracleClient;

#[derive(Debug)]
pub struct MemoryChannel {
    oracle: MemoryOracleClient,
    key: spin::RwLock<PreimageKey>,
}

impl Clone for MemoryChannel {
    fn clone(&self) -> Self {
        MemoryChannel {
            oracle: self.oracle.clone(),
            key: spin::RwLock::new(PreimageKey::default())
        }
    }
}

#[async_trait::async_trait]
impl Channel for MemoryChannel {
    async fn read(&self, buf: &mut [u8]) -> ChannelResult<usize> {
        tracing::info!("read");
        let key = self.key.read();
        let data = self.oracle.get(*key).await.unwrap();
        buf.copy_from_slice(data.as_slice());
        Ok(data.len())
    }

    async fn read_exact(&self, buf: &mut [u8]) ->ChannelResult<usize>  {
        tracing::info!("read exact");
        let key = self.key.read();
        let data = self.oracle.get(*key).await.unwrap();
        buf.copy_from_slice(data.as_slice());
        Ok(data.len())
    }

    async fn write(&self, buf: &[u8]) -> ChannelResult<usize> {
        tracing::info!("write");
        let key : [u8; 32] = buf.try_into().unwrap();
        let key : PreimageKey = key.try_into().unwrap();
        let data = self.oracle.get(key).await.unwrap();
        let mut lock = self.key.write();
        *lock = key;
        Ok(data.len())
    }
}

impl MemoryChannel {

    pub fn from(client: MemoryOracleClient) -> Self {
        MemoryChannel {
            oracle: client,
            key: spin::RwLock::new(PreimageKey::default())
        }
    }

}