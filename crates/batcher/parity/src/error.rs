//! Parity normalization errors.

use base_blobs::BlobDecodeError;
use base_protocol::FrameParseError;

/// Error returned while normalizing a batcher DA submission.
#[derive(Debug, thiserror::Error)]
pub enum ParityError {
    /// The blob payload failed Base blob decoding.
    #[error("failed to decode blob payload: {0}")]
    BlobDecode(#[from] BlobDecodeError),
    /// The decoded payload failed batcher frame parsing.
    #[error("failed to parse batcher frames: {0}")]
    FrameParse(#[from] FrameParseError),
}
