use alloc::vec;
use alloc::vec::Vec;
use alloy_primitives::B256;
use kona_preimage::PreimageKey;

#[derive(::prost::Message, Clone, PartialEq)]
pub struct Preimage {
    #[prost(bytes = "vec", tag = "1")]
    pub key: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub data: Vec<u8>,
}

impl Preimage {
    pub fn new(key: PreimageKey, data: Vec<u8>) -> Self {
        Self {
            key: B256::from(key).0.to_vec(),
            data,
        }
    }
}

#[derive(::prost::Message, Clone, PartialEq)]
pub struct Preimages {
    #[prost(message, repeated, tag = "1")]
    pub preimages: Vec<Preimage>,
}


#[cfg(test)]
mod test {
    use alloc::vec;
    use alloc::vec::Vec;
    use prost::Message;
    use crate::types::{Preimage, Preimages};

    #[test]
    pub fn test_preimage_encode_decode() {
        let expected = Preimage {
            key: vec![1, 2, 3],
            data: vec![4, 5, 6],
        };
        let mut buf: Vec<u8> = Vec::new();
        expected.encode(&mut buf).unwrap();

        let actual = Preimage::decode(&*buf).unwrap();
        assert_eq!(expected, actual);
    }

    #[test]
    pub fn test_preimages_encode_decode() {
        let expected = Preimages {
            preimages: vec![
                Preimage {
                    key: vec![1, 2, 3],
                    data: vec![4, 5, 6],
                },
                Preimage {
                    key: vec![7, 8, 9],
                    data: vec![10, 11, 12],
                },
            ],
        };
        let mut buf: Vec<u8> = Vec::new();
        expected.encode(&mut buf).unwrap();

        let actual = Preimages::decode(&*buf).unwrap();
        assert_eq!(expected, actual);
    }
}
