use crate::errors::Error;
use crate::header::{Header, OPTIMISM_HEADER_TYPE_URL};
use crate::misbehaviour::Misbehaviour;
use light_client::types::Any;

#[derive(Clone, Debug)]
#[allow(clippy::large_enum_variant)]
pub enum ClientMessage<const L1_SYNC_COMMITTEE_SIZE: usize> {
    Header(Header<L1_SYNC_COMMITTEE_SIZE>),
    Misbehaviour(Misbehaviour<L1_SYNC_COMMITTEE_SIZE>),
}

impl<const L1_SYNC_COMMITTEE_SIZE: usize> TryFrom<Any> for ClientMessage<L1_SYNC_COMMITTEE_SIZE> {
    type Error = Error;

    fn try_from(value: Any) -> Result<Self, Self::Error> {
        match value.type_url.as_str() {
            OPTIMISM_HEADER_TYPE_URL => Ok(ClientMessage::Header(Header::try_from(value)?)),
            _ => Ok(ClientMessage::Misbehaviour(Misbehaviour::try_from(value)?)),
        }
    }
}
