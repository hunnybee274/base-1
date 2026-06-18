//! Shadow-mode batch inbox parity monitoring.

use std::{
    collections::{HashMap, VecDeque},
    sync::Arc,
    time::Duration,
};

use alloy_primitives::{Address, Bytes};
use alloy_provider::{Provider, RootProvider};
use alloy_rpc_types_eth::{Block, BlockNumberOrTag, Transaction, TransactionTrait};
use base_batcher_parity::{NormalizedBatch, ParityComparator, ParityError, ParityNormalizer};
use base_blobs::BlobDecoder;
use base_common_genesis::RollupConfig;
use base_consensus_derive::BlobProvider;
use base_consensus_providers::{BeaconClient, OnlineBeaconClient, OnlineBlobProvider};
use base_protocol::{BlockInfo, Channel, ChannelId, Frame};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};
use url::Url;

use crate::BatcherServiceMetrics;

/// Runtime configuration for the shadow parity monitor.
#[derive(Debug, Clone)]
pub struct ShadowParityMonitorConfig {
    /// Canonical rollup batch inbox used by the op-batcher.
    pub canonical_inbox: Address,
    /// Shadow batch inbox used by this base-batcher instance.
    pub shadow_inbox: Address,
    /// L1 polling interval.
    pub poll_interval: Duration,
    /// Number of recent L1 blocks to scan on startup.
    pub start_depth: u64,
    /// Rollup config used to decode submitted channels.
    pub rollup_config: Arc<RollupConfig>,
    /// Optional L1 beacon API URL used to fetch blob sidecars.
    pub l1_beacon_url: Option<Url>,
}

/// Continuously compares canonical and shadow batch inbox submissions.
#[derive(Debug)]
pub struct ShadowParityMonitor {
    /// L1 execution provider.
    pub l1_provider: RootProvider,
    /// Optional blob sidecar provider.
    pub blob_provider: Option<OnlineBlobProvider<OnlineBeaconClient>>,
    /// Monitor configuration.
    pub config: ShadowParityMonitorConfig,
    /// Stateful channel and decoded-batch comparison state.
    pub state: ParityState,
}

/// Side of the parity comparison.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParitySide {
    /// Canonical op-batcher submissions to the rollup-config inbox.
    Canonical,
    /// Shadow base-batcher submissions to the override inbox.
    Shadow,
}

/// Result counts from one comparison pass.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ParityCompareStats {
    /// Number of matching batches compared.
    pub matches: usize,
    /// Number of diverging batches compared.
    pub divergences: usize,
}

/// Stateful parity comparison data.
#[derive(Debug, Default)]
pub struct ParityState {
    /// Canonical side channel/batch state.
    pub canonical: ParitySideState,
    /// Shadow side channel/batch state.
    pub shadow: ParitySideState,
    /// Last comparison result, if any comparison has completed.
    pub last_result: Option<bool>,
}

/// Channel assembler and decoded-batch queue for one side.
#[derive(Debug, Default)]
pub struct ParitySideState {
    /// Channels currently waiting for missing frames.
    pub channels: HashMap<ChannelId, Channel>,
    /// Channel first-seen order.
    pub channel_order: VecDeque<ChannelId>,
    /// Decoded batches waiting for the opposite side.
    pub batches: VecDeque<NormalizedBatch>,
}

impl ShadowParityMonitor {
    /// Create a new shadow parity monitor.
    pub async fn new(
        l1_provider: RootProvider,
        config: ShadowParityMonitorConfig,
    ) -> eyre::Result<Self> {
        let blob_provider = match config.l1_beacon_url.as_ref() {
            Some(url) => Some(Self::build_blob_provider(url).await?),
            None => None,
        };

        Ok(Self { l1_provider, blob_provider, config, state: ParityState::default() })
    }

    /// Build an online blob provider from an L1 beacon API URL.
    pub async fn build_blob_provider(
        url: &Url,
    ) -> eyre::Result<OnlineBlobProvider<OnlineBeaconClient>> {
        let beacon_client = OnlineBeaconClient::new_http(url.as_str().to_owned());
        let genesis_time = beacon_client
            .genesis_time()
            .await
            .map_err(|e| eyre::eyre!("failed to fetch L1 beacon genesis time: {e}"))?
            .data
            .genesis_time;
        let slot_interval = beacon_client
            .slot_interval()
            .await
            .map_err(|e| eyre::eyre!("failed to fetch L1 beacon slot interval: {e}"))?
            .data
            .seconds_per_slot;

        Ok(OnlineBlobProvider { beacon_client, genesis_time, slot_interval })
    }

    /// Spawn the monitor as a background task.
    pub fn spawn(self, cancellation: CancellationToken) -> tokio::task::JoinHandle<()> {
        tokio::spawn(self.run(cancellation))
    }

    /// Run the monitor until cancellation.
    pub async fn run(mut self, cancellation: CancellationToken) {
        BatcherServiceMetrics::enabled().set(1.0);
        info!(
            canonical_inbox = %self.config.canonical_inbox,
            shadow_inbox = %self.config.shadow_inbox,
            start_depth = %self.config.start_depth,
            beacon_configured = self.config.l1_beacon_url.is_some(),
            "shadow parity monitor running"
        );

        let mut next_l1 = loop {
            match self.initial_l1_block().await {
                Ok(block) => break block,
                Err(e) => {
                    BatcherServiceMetrics::l1_fetch_errors_total().increment(1);
                    warn!(error = %e, "failed to initialize shadow parity L1 cursor");
                    if !self.wait_for_next_poll(&cancellation).await {
                        return;
                    }
                }
            }
        };

        loop {
            let head = match self.l1_provider.get_block_number().await {
                Ok(head) => head,
                Err(e) => {
                    BatcherServiceMetrics::l1_fetch_errors_total().increment(1);
                    warn!(error = %e, "failed to fetch L1 head for shadow parity monitor");
                    if !self.wait_for_next_poll(&cancellation).await {
                        break;
                    }
                    continue;
                }
            };

            while next_l1 <= head {
                match self.process_l1_block(next_l1).await {
                    Ok(()) => {
                        next_l1 = next_l1.saturating_add(1);
                    }
                    Err(e) => {
                        BatcherServiceMetrics::l1_fetch_errors_total().increment(1);
                        warn!(
                            error = %e,
                            l1_block = %next_l1,
                            "failed to process L1 block for shadow parity monitor"
                        );
                        break;
                    }
                }
            }

            if !self.wait_for_next_poll(&cancellation).await {
                break;
            }
        }
        BatcherServiceMetrics::enabled().set(0.0);
        info!("shadow parity monitor stopped");
    }

    /// Fetch the initial L1 block number to process.
    pub async fn initial_l1_block(&self) -> eyre::Result<u64> {
        let head = self
            .l1_provider
            .get_block_number()
            .await
            .map_err(|e| eyre::eyre!("failed to fetch L1 head: {e}"))?;
        Ok(head.saturating_sub(self.config.start_depth.saturating_sub(1)))
    }

    /// Sleep for one polling interval, returning false if cancellation fired.
    pub async fn wait_for_next_poll(&self, cancellation: &CancellationToken) -> bool {
        tokio::select! {
            biased;
            () = cancellation.cancelled() => false,
            () = tokio::time::sleep(self.config.poll_interval) => true,
        }
    }

    /// Process one L1 block.
    pub async fn process_l1_block(&mut self, block_number: u64) -> eyre::Result<()> {
        let block = self
            .l1_provider
            .get_block_by_number(BlockNumberOrTag::Number(block_number))
            .full()
            .await
            .map_err(|e| eyre::eyre!("failed to fetch L1 block {block_number}: {e}"))?
            .ok_or_else(|| eyre::eyre!("L1 block {block_number} not found"))?;
        let block_info = Self::block_info(&block);

        for tx in block.transactions.txns() {
            // The monitor intentionally keys off inbox address only: shadow
            // deployments know their override inbox, while the canonical
            // op-batcher signer is owned by the separate production deployment.
            let side = match tx.inner.to() {
                Some(to) if to == self.config.canonical_inbox => Some(ParitySide::Canonical),
                Some(to) if to == self.config.shadow_inbox => Some(ParitySide::Shadow),
                _ => None,
            };
            let Some(side) = side else { continue };
            self.process_transaction(side, tx, &block_info).await;
        }

        let stats = self.state.compare_ready(block_number);
        self.state.record_pending_metrics();
        self.state.record_alignment_metric();
        BatcherServiceMetrics::latest_l1_block().set(block_number as f64);

        if stats.matches > 0 || stats.divergences > 0 {
            debug!(
                l1_block = %block_number,
                matches = %stats.matches,
                divergences = %stats.divergences,
                canonical_pending = %self.state.canonical.pending_batches(),
                shadow_pending = %self.state.shadow.pending_batches(),
                "shadow parity comparisons processed"
            );
        }

        Ok(())
    }

    /// Convert an RPC block to derivation block info.
    pub fn block_info(block: &Block<Transaction>) -> BlockInfo {
        BlockInfo {
            hash: block.header.hash,
            number: block.header.number,
            parent_hash: block.header.inner.parent_hash,
            timestamp: block.header.inner.timestamp,
        }
    }

    /// Process one inbox transaction.
    pub async fn process_transaction(
        &mut self,
        side: ParitySide,
        tx: &Transaction,
        block_info: &BlockInfo,
    ) {
        let Some(blob_hashes) = tx.blob_versioned_hashes() else {
            self.process_calldata_payload(side, tx.inner.input(), *block_info);
            return;
        };

        if blob_hashes.is_empty() {
            self.process_calldata_payload(side, tx.inner.input(), *block_info);
            return;
        }

        let Some(blob_provider) = self.blob_provider.as_mut() else {
            BatcherServiceMetrics::missing_beacon_total().increment(blob_hashes.len() as u64);
            warn!(
                l1_block = %block_info.number,
                blob_count = %blob_hashes.len(),
                "cannot process blob submissions for shadow parity without an L1 beacon URL"
            );
            return;
        };

        let blobs = match blob_provider.get_and_validate_blobs(block_info, blob_hashes).await {
            Ok(blobs) => blobs,
            Err(e) => {
                BatcherServiceMetrics::blob_fetch_errors_total().increment(1);
                warn!(
                    error = %e,
                    l1_block = %block_info.number,
                    blob_count = %blob_hashes.len(),
                    "failed to fetch blob sidecars for shadow parity"
                );
                return;
            }
        };

        for blob in blobs {
            match BlobDecoder::decode(blob.as_ref()) {
                Ok(data) => self.process_blob_payload(side, data, *block_info),
                Err(e) => {
                    BatcherServiceMetrics::extraction_errors_total().increment(1);
                    warn!(
                        error = %e,
                        l1_block = %block_info.number,
                        "failed to decode blob payload for shadow parity"
                    );
                }
            }
        }
    }

    /// Process one calldata payload.
    pub fn process_calldata_payload(
        &mut self,
        side: ParitySide,
        payload: &[u8],
        block_info: BlockInfo,
    ) {
        if payload.is_empty() {
            return;
        }
        side.increment_payloads();
        self.ingest_payload(side, payload, block_info);
    }

    /// Process one decoded blob payload.
    pub fn process_blob_payload(
        &mut self,
        side: ParitySide,
        payload: Bytes,
        block_info: BlockInfo,
    ) {
        side.increment_payloads();
        self.ingest_payload(side, payload.as_ref(), block_info);
    }

    /// Parse and ingest frame data from one DA payload.
    pub fn ingest_payload(&mut self, side: ParitySide, payload: &[u8], block_info: BlockInfo) {
        match self.state.ingest_payload(side, payload, block_info, &self.config.rollup_config) {
            Ok(decoded) => {
                if decoded.complete_channels > 0 {
                    side.increment_complete_channels(decoded.complete_channels as u64);
                    side.increment_batches(decoded.batches as u64);
                }
            }
            Err(e) => {
                BatcherServiceMetrics::extraction_errors_total().increment(1);
                warn!(
                    error = %e,
                    l1_block = %block_info.number,
                    "failed to ingest shadow parity payload"
                );
            }
        }
    }
}

impl ParitySide {
    /// Increment the payload counter for this side.
    pub fn increment_payloads(self) {
        match self {
            Self::Canonical => BatcherServiceMetrics::canonical_payloads_total().increment(1),
            Self::Shadow => BatcherServiceMetrics::shadow_payloads_total().increment(1),
        }
    }

    /// Increment the complete-channel counter for this side.
    pub fn increment_complete_channels(self, count: u64) {
        match self {
            Self::Canonical => {
                BatcherServiceMetrics::canonical_complete_channels_total().increment(count);
            }
            Self::Shadow => {
                BatcherServiceMetrics::shadow_complete_channels_total().increment(count);
            }
        }
    }

    /// Increment the decoded-batch counter for this side.
    pub fn increment_batches(self, count: u64) {
        match self {
            Self::Canonical => {
                BatcherServiceMetrics::canonical_batches_total().increment(count);
            }
            Self::Shadow => {
                BatcherServiceMetrics::shadow_batches_total().increment(count);
            }
        }
    }
}

/// Result from ingesting one payload into a side state.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct IngestedPayload {
    /// Number of complete channels decoded.
    pub complete_channels: usize,
    /// Number of decoded batches added to the comparison queue.
    pub batches: usize,
}

impl ParityState {
    /// Ingest one DA payload into the selected side.
    pub fn ingest_payload(
        &mut self,
        side: ParitySide,
        payload: &[u8],
        block_info: BlockInfo,
        rollup_config: &RollupConfig,
    ) -> Result<IngestedPayload, ParityError> {
        match side {
            ParitySide::Canonical => {
                self.canonical.ingest_payload(payload, block_info, rollup_config)
            }
            ParitySide::Shadow => self.shadow.ingest_payload(payload, block_info, rollup_config),
        }
    }

    /// Compare all currently paired decoded batches.
    pub fn compare_ready(&mut self, l1_block: u64) -> ParityCompareStats {
        let mut stats = ParityCompareStats::default();
        while let (Some(canonical), Some(shadow)) =
            (self.canonical.batches.pop_front(), self.shadow.batches.pop_front())
        {
            let comparison = ParityComparator::compare(
                std::slice::from_ref(&canonical),
                std::slice::from_ref(&shadow),
            );
            if comparison.is_match {
                stats.matches += 1;
                self.last_result = Some(true);
                BatcherServiceMetrics::matches_total().increment(1);
                BatcherServiceMetrics::last_match_l1_block().set(l1_block as f64);
            } else {
                stats.divergences += 1;
                self.last_result = Some(false);
                BatcherServiceMetrics::divergences_total().increment(1);
                BatcherServiceMetrics::last_divergence_l1_block().set(l1_block as f64);
                warn!(
                    l1_block = %l1_block,
                    canonical_start_timestamp = %canonical.start_timestamp,
                    canonical_end_timestamp = %canonical.end_timestamp,
                    canonical_start_epoch = %canonical.start_epoch_num,
                    canonical_end_epoch = %canonical.end_epoch_num,
                    shadow_start_timestamp = %shadow.start_timestamp,
                    shadow_end_timestamp = %shadow.end_timestamp,
                    shadow_start_epoch = %shadow.start_epoch_num,
                    shadow_end_epoch = %shadow.end_epoch_num,
                    "shadow parity divergence detected"
                );
            }
        }
        stats
    }

    /// Record pending-batch gauges.
    pub fn record_pending_metrics(&self) {
        BatcherServiceMetrics::canonical_pending_batches()
            .set(self.canonical.pending_batches() as f64);
        BatcherServiceMetrics::shadow_pending_batches().set(self.shadow.pending_batches() as f64);
    }

    /// Record the alignment gauge.
    pub fn record_alignment_metric(&self) {
        if let Some(aligned) = self.is_aligned() {
            BatcherServiceMetrics::aligned().set(if aligned { 1.0 } else { 0.0 });
        }
    }

    /// Return the current alignment state, if at least one comparison has completed.
    pub fn is_aligned(&self) -> Option<bool> {
        let last_result = self.last_result?;
        Some(
            last_result
                && self.canonical.pending_batches() == 0
                && self.shadow.pending_batches() == 0,
        )
    }
}

impl ParitySideState {
    /// Ingest one DA payload into this side.
    pub fn ingest_payload(
        &mut self,
        payload: &[u8],
        block_info: BlockInfo,
        rollup_config: &RollupConfig,
    ) -> Result<IngestedPayload, ParityError> {
        let frames = Frame::parse_frames(payload)?;
        for frame in frames {
            self.ingest_frame(frame, block_info);
        }
        self.drain_ready_channels(block_info.timestamp, rollup_config)
    }

    /// Ingest one frame.
    pub fn ingest_frame(&mut self, frame: Frame, block_info: BlockInfo) {
        if !self.channels.contains_key(&frame.id) {
            self.channel_order.push_back(frame.id);
        }
        let channel =
            self.channels.entry(frame.id).or_insert_with(|| Channel::new(frame.id, block_info));
        if let Err(e) = channel.add_frame(frame, block_info) {
            BatcherServiceMetrics::extraction_errors_total().increment(1);
            debug!(
                error = %e,
                l1_block = %block_info.number,
                "rejected shadow parity frame"
            );
        }
    }

    /// Drain every ready channel into the decoded-batch queue.
    pub fn drain_ready_channels(
        &mut self,
        inclusion_timestamp: u64,
        rollup_config: &RollupConfig,
    ) -> Result<IngestedPayload, ParityError> {
        let ready_ids = self
            .channel_order
            .iter()
            .copied()
            .filter(|id| self.channels.get(id).is_some_and(Channel::is_ready))
            .collect::<Vec<_>>();
        let mut result = IngestedPayload::default();

        for id in ready_ids {
            self.channel_order.retain(|queued| queued != &id);
            let Some(channel) = self.channels.remove(&id) else { continue };
            let batches = ParityNormalizer::try_normalize_channel(
                &channel,
                inclusion_timestamp,
                rollup_config,
            )?;
            result.complete_channels += 1;
            result.batches += batches.len();
            self.batches.extend(batches);
        }

        Ok(result)
    }

    /// Number of decoded batches waiting for comparison.
    pub fn pending_batches(&self) -> usize {
        self.batches.len()
    }
}

#[cfg(test)]
mod tests {
    use alloy_primitives::B256;

    use super::*;

    fn normalized_batch(timestamp: u64) -> NormalizedBatch {
        NormalizedBatch {
            kind: base_batcher_parity::NormalizedBatchKind::Single,
            parent_hash: Some(B256::repeat_byte(1)),
            epoch_hash: Some(B256::repeat_byte(2)),
            parent_check: None,
            l1_origin_check: None,
            chain_id: None,
            origin_bits: None,
            start_timestamp: timestamp,
            end_timestamp: timestamp,
            start_epoch_num: 10,
            end_epoch_num: 10,
            block_count: 1,
            tx_counts: vec![0],
            tx_hashes: vec![],
        }
    }

    #[test]
    fn compare_ready_records_match() {
        let mut state = ParityState::default();
        state.canonical.batches.push_back(normalized_batch(100));
        state.shadow.batches.push_back(normalized_batch(100));

        let stats = state.compare_ready(50);

        assert_eq!(stats.matches, 1);
        assert_eq!(stats.divergences, 0);
        assert_eq!(state.canonical.pending_batches(), 0);
        assert_eq!(state.shadow.pending_batches(), 0);
        assert_eq!(state.is_aligned(), Some(true));
    }

    #[test]
    fn compare_ready_records_divergence() {
        let mut state = ParityState::default();
        state.canonical.batches.push_back(normalized_batch(100));
        state.shadow.batches.push_back(normalized_batch(102));

        let stats = state.compare_ready(50);

        assert_eq!(stats.matches, 0);
        assert_eq!(stats.divergences, 1);
        assert_eq!(state.is_aligned(), Some(false));
    }

    #[test]
    fn pending_batches_are_not_aligned() {
        let mut state = ParityState::default();
        state.canonical.batches.push_back(normalized_batch(100));
        state.shadow.batches.push_back(normalized_batch(100));
        state.compare_ready(50);
        state.canonical.batches.push_back(normalized_batch(102));

        assert_eq!(state.is_aligned(), Some(false));
    }
}
