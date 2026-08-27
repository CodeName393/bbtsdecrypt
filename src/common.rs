use std::error::Error;

pub(crate) const TS_PACKET_SIZE: usize = 188;
pub(crate) type AppResult<T> = Result<T, Box<dyn Error>>;
