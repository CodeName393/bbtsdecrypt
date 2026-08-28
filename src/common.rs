use std::error::Error;

pub(crate) type AppResult<T> = Result<T, Box<dyn Error>>;
pub(crate) const TS_PACKET_SIZE: usize = 188;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum VideoMode {
    Sdr,
    Hdr,
    DolbyVision,
}

