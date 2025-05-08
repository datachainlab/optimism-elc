use kona_preimage::{Channel, PreimageKey, PreimageOracleClient};
use kona_preimage::errors::ChannelResult;
use crate::oracle::MemoryOracleClient;
use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;
use core::slice::SlicePattern;

#[derive(Debug)]
pub struct MemoryChannel {
    oracle: MemoryOracleClient,
    current: spin::RwLock<Vec<u8>>,
}

impl Clone for MemoryChannel {
    fn clone(&self) -> Self {
        MemoryChannel {
            oracle: self.oracle.clone(),
            current: spin::RwLock::new(vec![])
        }
    }
}

#[async_trait::async_trait]
impl Channel for MemoryChannel {
    async fn read(&self, buf: &mut [u8]) -> ChannelResult<usize> {
        self.read_exact(buf).await
    }

    async fn read_exact(&self, buf: &mut [u8]) ->ChannelResult<usize>  {
        //TODO adjust OracleReader behavior
        let data = self.current.read().as_slice();
        buf.copy_from_slice(data);
        Ok(data.len())
    }

    async fn write(&self, buf: &[u8]) -> ChannelResult<usize> {
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