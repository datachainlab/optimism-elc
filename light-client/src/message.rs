use crate::errors::Error;
use light_client::types::Any;
use crate::header::Header;

#[derive(Clone, Debug)]
#[allow(clippy::large_enum_variant)]
pub enum ClientMessage<const L1_SYNC_COMMITTEE_SIZE: usize> {
    Header(Header<L1_SYNC_COMMITTEE_SIZE>),
    Misbehaviour,
}

impl <const L1_SYNC_COMMITTEE_SIZE: usize> TryFrom<Any> for ClientMessage<L1_SYNC_COMMITTEE_SIZE> {
    type Error = Error;

    fn try_from(value: Any) -> Result<Self, Self::Error> {
        match value.type_url.as_str() {
            OPTIMISM_HEADER_TYPE_URL => Ok(ClientMessage::Header(Header::try_from(value)?)),
            //TODO misibehavior
            _ => Err(Error::UnexpectedClientType(value.type_url.clone())),
        }
    }
}
