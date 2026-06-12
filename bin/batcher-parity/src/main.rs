//! CLI glue for normalized batcher parity checks.

use alloy_eips::eip4844::{BYTES_PER_BLOB, Blob};
use alloy_primitives::hex;
use base_batcher_parity::{NormalizedSubmission, ParityComparator, ParityNormalizer};
use base_common_chains::ChainConfig;
use clap::Parser;
use serde::Serialize;

/// Compare two batcher DA submissions after normalizing frame and channel metadata.
#[derive(Debug, Parser)]
#[command(author, version = env!("CARGO_PKG_VERSION"), about)]
struct Cli {
    /// Built-in Base chain name: base, base-sepolia, base-zeronet, or dev.
    #[arg(long = "chain")]
    chain: String,

    /// L1 inclusion timestamp used for channel decompression fork gates.
    #[arg(long = "inclusion-timestamp")]
    inclusion_timestamp: u64,

    /// Left calldata payload as hex, including the derivation version byte.
    #[arg(long = "left-calldata-hex", conflicts_with = "left_blob_hex")]
    left_calldata_hex: Option<String>,

    /// Right calldata payload as hex, including the derivation version byte.
    #[arg(long = "right-calldata-hex", conflicts_with = "right_blob_hex")]
    right_calldata_hex: Option<String>,

    /// Left EIP-4844 blob as hex.
    #[arg(long = "left-blob-hex", conflicts_with = "left_calldata_hex")]
    left_blob_hex: Option<String>,

    /// Right EIP-4844 blob as hex.
    #[arg(long = "right-blob-hex", conflicts_with = "right_calldata_hex")]
    right_blob_hex: Option<String>,
}

/// JSON output for one normalized parity comparison.
#[derive(Debug, Serialize)]
struct Report {
    /// Normalized left submission.
    left: NormalizedSubmission,
    /// Normalized right submission.
    right: NormalizedSubmission,
    /// Batch-list comparison.
    comparison: base_batcher_parity::ParityComparison,
}

enum SubmissionInput {
    Calldata(Vec<u8>),
    Blob(Box<Blob>),
}

impl Cli {
    fn run(self) -> eyre::Result<()> {
        let chain = ChainConfig::by_name(&self.chain)
            .ok_or_else(|| eyre::eyre!("unsupported chain: {}", self.chain))?;
        let rollup_config = chain.rollup_config();
        let left_input =
            Self::submission_input(self.left_calldata_hex, self.left_blob_hex, "left")?;
        let right_input =
            Self::submission_input(self.right_calldata_hex, self.right_blob_hex, "right")?;

        let left = Self::normalize(left_input, self.inclusion_timestamp, &rollup_config)?;
        let right = Self::normalize(right_input, self.inclusion_timestamp, &rollup_config)?;
        let comparison = ParityComparator::compare(&left.batches, &right.batches);
        let report = Report { left, right, comparison };

        println!("{}", serde_json::to_string_pretty(&report)?);
        Ok(())
    }

    fn submission_input(
        calldata_hex: Option<String>,
        blob_hex: Option<String>,
        side: &str,
    ) -> eyre::Result<SubmissionInput> {
        match (calldata_hex, blob_hex) {
            (Some(data), None) => Ok(SubmissionInput::Calldata(Self::decode_hex(&data)?)),
            (None, Some(data)) => {
                let decoded = Self::decode_hex(&data)?;
                let blob: [u8; BYTES_PER_BLOB] =
                    decoded.try_into().map_err(|decoded: Vec<u8>| {
                        eyre::eyre!(
                            "{side} blob must be {} bytes, got {}",
                            BYTES_PER_BLOB,
                            decoded.len()
                        )
                    })?;
                Ok(SubmissionInput::Blob(Box::new(Blob::from(blob))))
            }
            (None, None) => {
                Err(eyre::eyre!("{side} submission requires calldata or blob hex input"))
            }
            (Some(_), Some(_)) => {
                Err(eyre::eyre!("{side} submission cannot set both calldata and blob hex input"))
            }
        }
    }

    fn decode_hex(value: &str) -> eyre::Result<Vec<u8>> {
        hex::decode(value.trim_start_matches("0x"))
            .map_err(|e| eyre::eyre!("invalid hex input: {e}"))
    }

    fn normalize(
        input: SubmissionInput,
        inclusion_timestamp: u64,
        rollup_config: &base_common_genesis::RollupConfig,
    ) -> eyre::Result<NormalizedSubmission> {
        match input {
            SubmissionInput::Calldata(data) => {
                Ok(ParityNormalizer::normalize_calldata(&data, inclusion_timestamp, rollup_config)?)
            }
            SubmissionInput::Blob(blob) => {
                Ok(ParityNormalizer::normalize_blob(&blob, inclusion_timestamp, rollup_config)?)
            }
        }
    }
}

fn main() -> eyre::Result<()> {
    Cli::parse().run()
}
