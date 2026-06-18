//! Shadow-mode batch inbox parity monitoring.

use std::{
    collections::{BTreeMap, HashMap, VecDeque},
    panic::AssertUnwindSafe,
    sync::Arc,
    time::Duration,
};

use alloy_primitives::{Address, Bytes};
use alloy_provider::{Provider, RootProvider};
use alloy_rpc_types_eth::{Block, BlockNumberOrTag, Transaction, TransactionTrait};
use base_batcher_parity::{
    NormalizedBatch, NormalizedL2Block, ParityComparator, ParityError, ParityNormalizer,
};
use base_blobs::BlobDecoder;
use base_common_genesis::RollupConfig;
use base_consensus_derive::BlobProvider;
use base_consensus_providers::{BeaconClient, OnlineBeaconClient, OnlineBlobProvider};
use base_protocol::{BlockInfo, Channel, ChannelId, Frame};
use futures::FutureExt;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};
use url::Url;

use crate::BatcherServiceMetrics;

/// Pending-batch queue delta that triggers an operator-facing drift warning.
pub const PENDING_QUEUE_DRIFT_WARN_THRESHOLD: usize = 10;

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
    /// Number of matching decoded L2 blocks compared by timestamp and content.
    pub l2_block_matches: usize,
    /// Number of diverging decoded L2 blocks compared by timestamp and content.
    pub l2_block_mismatches: usize,
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
    /// Last decoded L2 block content comparison result, if any has completed.
    pub last_l2_result: Option<bool>,
    /// Last pending queue drift reported to logs.
    pub last_reported_pending_drift: usize,
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
    /// Decoded L2 blocks waiting for the opposite side, keyed by L2 timestamp.
    pub l2_blocks: BTreeMap<u64, VecDeque<NormalizedL2Block>>,
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
        tokio::spawn(async move {
            if AssertUnwindSafe(self.run(cancellation)).catch_unwind().await.is_err() {
                BatcherServiceMetrics::enabled().set(0.0);
                error!("shadow parity monitor panicked");
            }
        })
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

        let evicted_channels = self.state.evict_expired_channels(
            block_info.number,
            block_info.timestamp,
            &self.config.rollup_config,
        );
        if evicted_channels > 0 {
            BatcherServiceMetrics::evicted_channels_total().increment(evicted_channels as u64);
            debug!(
                l1_block = %block_number,
                evicted_channels = %evicted_channels,
                "evicted stale shadow parity channels"
            );
        }

        let stats = self.state.compare_ready(block_number);
        self.state.record_pending_metrics();
        self.state.warn_on_pending_drift(block_number);
        self.state.record_alignment_metric();
        BatcherServiceMetrics::latest_l1_block().set(block_number as f64);

        if stats.matches > 0
            || stats.divergences > 0
            || stats.l2_block_matches > 0
            || stats.l2_block_mismatches > 0
        {
            debug!(
                l1_block = %block_number,
                matches = %stats.matches,
                divergences = %stats.divergences,
                l2_block_matches = %stats.l2_block_matches,
                l2_block_mismatches = %stats.l2_block_mismatches,
                canonical_pending = %self.state.canonical.pending_batches(),
                shadow_pending = %self.state.shadow.pending_batches(),
                canonical_l2_pending = %self.state.canonical.pending_l2_blocks(),
                shadow_l2_pending = %self.state.shadow.pending_l2_blocks(),
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
                    side.increment_l2_blocks(decoded.l2_blocks as u64);
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

    /// Increment the decoded L2 block counter for this side.
    pub fn increment_l2_blocks(self, count: u64) {
        match self {
            Self::Canonical => {
                BatcherServiceMetrics::canonical_l2_blocks_total().increment(count);
            }
            Self::Shadow => {
                BatcherServiceMetrics::shadow_l2_blocks_total().increment(count);
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
    /// Number of decoded L2 blocks added to the comparison queue.
    pub l2_blocks: usize,
    /// Number of complete channels that failed strict batch decoding.
    pub decode_errors: usize,
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
        // Comparisons are intentionally positional: once one side emits an
        // extra or missing batch, the pending queue delta below is the operator
        // signal that later comparisons may be offset rather than independently
        // divergent.
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
        let l2_stats = self.compare_l2_blocks(l1_block);
        stats.l2_block_matches = l2_stats.l2_block_matches;
        stats.l2_block_mismatches = l2_stats.l2_block_mismatches;
        stats
    }

    /// Compare decoded L2 blocks by timestamp and content, independent of submission order.
    pub fn compare_l2_blocks(&mut self, l1_block: u64) -> ParityCompareStats {
        let timestamps = self
            .canonical
            .l2_blocks
            .keys()
            .copied()
            .filter(|timestamp| self.shadow.l2_blocks.contains_key(timestamp))
            .collect::<Vec<_>>();
        let mut stats = ParityCompareStats::default();

        for timestamp in timestamps {
            let pair_count = self
                .canonical
                .l2_blocks
                .get(&timestamp)
                .map_or(0, VecDeque::len)
                .min(self.shadow.l2_blocks.get(&timestamp).map_or(0, VecDeque::len));

            for _ in 0..pair_count {
                let Some(canonical) = self.canonical.pop_l2_block(timestamp) else {
                    continue;
                };
                let Some(shadow) = self.shadow.pop_l2_block(timestamp) else {
                    self.canonical.push_l2_block(canonical);
                    continue;
                };

                if canonical.content_matches(&shadow) {
                    stats.l2_block_matches += 1;
                    self.last_l2_result = Some(true);
                    BatcherServiceMetrics::l2_block_matches_total().increment(1);
                    if canonical.tx_count() > 0 {
                        BatcherServiceMetrics::l2_block_non_empty_matches_total().increment(1);
                    }
                    BatcherServiceMetrics::last_l2_block_match_timestamp().set(timestamp as f64);
                    BatcherServiceMetrics::last_l2_block_match_l1_block().set(l1_block as f64);
                } else {
                    stats.l2_block_mismatches += 1;
                    self.last_l2_result = Some(false);
                    BatcherServiceMetrics::l2_block_mismatches_total().increment(1);
                    BatcherServiceMetrics::last_l2_block_mismatch_timestamp().set(timestamp as f64);
                    BatcherServiceMetrics::last_l2_block_mismatch_l1_block().set(l1_block as f64);

                    let reason = if canonical.epoch_num != shadow.epoch_num {
                        BatcherServiceMetrics::l2_block_origin_mismatches_total().increment(1);
                        "origin"
                    } else if canonical.tx_count() != shadow.tx_count() {
                        BatcherServiceMetrics::l2_block_tx_count_mismatches_total().increment(1);
                        "tx_count"
                    } else {
                        BatcherServiceMetrics::l2_block_tx_hash_mismatches_total().increment(1);
                        "tx_hash"
                    };

                    warn!(
                        l1_block = %l1_block,
                        l2_timestamp = %timestamp,
                        canonical_epoch = %canonical.epoch_num,
                        shadow_epoch = %shadow.epoch_num,
                        canonical_tx_count = %canonical.tx_count(),
                        shadow_tx_count = %shadow.tx_count(),
                        reason,
                        "shadow parity L2 block content divergence detected"
                    );
                }
            }
        }

        stats
    }

    /// Record pending-batch gauges.
    pub fn record_pending_metrics(&self) {
        BatcherServiceMetrics::canonical_pending_batches()
            .set(self.canonical.pending_batches() as f64);
        BatcherServiceMetrics::shadow_pending_batches().set(self.shadow.pending_batches() as f64);
        BatcherServiceMetrics::pending_batch_delta().set(self.pending_batch_delta() as f64);
        BatcherServiceMetrics::canonical_pending_l2_blocks()
            .set(self.canonical.pending_l2_blocks() as f64);
        BatcherServiceMetrics::shadow_pending_l2_blocks()
            .set(self.shadow.pending_l2_blocks() as f64);
        BatcherServiceMetrics::pending_l2_block_delta().set(self.pending_l2_block_delta() as f64);
        BatcherServiceMetrics::oldest_unmatched_canonical_l2_timestamp()
            .set(self.canonical.oldest_l2_timestamp().unwrap_or_default() as f64);
        BatcherServiceMetrics::oldest_unmatched_shadow_l2_timestamp()
            .set(self.shadow.oldest_l2_timestamp().unwrap_or_default() as f64);
    }

    /// Warn when positional comparison queues are persistently drifting apart.
    pub fn warn_on_pending_drift(&mut self, l1_block: u64) {
        let drift = self.pending_batch_delta();
        if drift < PENDING_QUEUE_DRIFT_WARN_THRESHOLD {
            self.last_reported_pending_drift = 0;
            return;
        }
        if drift == self.last_reported_pending_drift {
            return;
        }
        self.last_reported_pending_drift = drift;
        warn!(
            l1_block = %l1_block,
            drift = %drift,
            canonical_pending = %self.canonical.pending_batches(),
            shadow_pending = %self.shadow.pending_batches(),
            "shadow parity pending queues drifted"
        );
    }

    /// Return the absolute pending-batch queue delta between sides.
    pub fn pending_batch_delta(&self) -> usize {
        self.canonical.pending_batches().abs_diff(self.shadow.pending_batches())
    }

    /// Return the absolute pending decoded L2 block delta between sides.
    pub fn pending_l2_block_delta(&self) -> usize {
        self.canonical.pending_l2_blocks().abs_diff(self.shadow.pending_l2_blocks())
    }

    /// Evict incomplete channels that have exceeded the rollup channel timeout.
    pub fn evict_expired_channels(
        &mut self,
        l1_block: u64,
        l1_timestamp: u64,
        rollup_config: &RollupConfig,
    ) -> usize {
        self.canonical.evict_expired_channels(l1_block, l1_timestamp, rollup_config)
            + self.shadow.evict_expired_channels(l1_block, l1_timestamp, rollup_config)
    }

    /// Record the alignment gauge.
    pub fn record_alignment_metric(&self) {
        if let Some(aligned) = self.is_aligned() {
            BatcherServiceMetrics::aligned().set(if aligned { 1.0 } else { 0.0 });
        }
    }

    /// Return the current alignment state, if at least one comparison has completed.
    pub fn is_aligned(&self) -> Option<bool> {
        if let Some(last_l2_result) = self.last_l2_result {
            return Some(
                last_l2_result
                    && self.canonical.pending_l2_blocks() == 0
                    && self.shadow.pending_l2_blocks() == 0,
            );
        }
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
        Ok(self.drain_ready_channels(block_info.timestamp, rollup_config))
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
    ) -> IngestedPayload {
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
            match ParityNormalizer::try_normalize_channel(
                &channel,
                inclusion_timestamp,
                rollup_config,
            ) {
                Ok(batches) => {
                    result.complete_channels += 1;
                    result.batches += batches.batches.len();
                    result.l2_blocks += batches.l2_blocks.len();
                    self.batches.extend(batches.batches);
                    for block in batches.l2_blocks {
                        self.push_l2_block(block);
                    }
                }
                Err(e) => {
                    result.decode_errors += 1;
                    BatcherServiceMetrics::extraction_errors_total().increment(1);
                    debug!(
                        error = %e,
                        channel = %alloy_primitives::hex::encode(id),
                        "skipping corrupted channel during shadow parity drain"
                    );
                }
            }
        }

        result
    }

    /// Evict incomplete channels that exceeded the rollup channel timeout.
    pub fn evict_expired_channels(
        &mut self,
        l1_block: u64,
        l1_timestamp: u64,
        rollup_config: &RollupConfig,
    ) -> usize {
        let timeout = rollup_config.channel_timeout(l1_timestamp);
        let expired = self
            .channel_order
            .iter()
            .copied()
            .filter(|id| {
                self.channels.get(id).is_some_and(|channel| {
                    channel.open_block_number().saturating_add(timeout) < l1_block
                })
            })
            .collect::<Vec<_>>();

        if expired.is_empty() {
            return 0;
        }

        for id in &expired {
            self.channels.remove(id);
        }
        self.channel_order.retain(|id| !expired.contains(id));
        expired.len()
    }

    /// Number of decoded batches waiting for comparison.
    pub fn pending_batches(&self) -> usize {
        self.batches.len()
    }

    /// Number of decoded L2 blocks waiting for content comparison.
    pub fn pending_l2_blocks(&self) -> usize {
        self.l2_blocks.values().map(VecDeque::len).sum()
    }

    /// Oldest decoded L2 block timestamp waiting for content comparison.
    pub fn oldest_l2_timestamp(&self) -> Option<u64> {
        self.l2_blocks.keys().next().copied()
    }

    /// Store one decoded L2 block for future content comparison.
    pub fn push_l2_block(&mut self, block: NormalizedL2Block) {
        self.l2_blocks.entry(block.timestamp).or_default().push_back(block);
    }

    /// Pop the oldest decoded L2 block for a timestamp.
    pub fn pop_l2_block(&mut self, timestamp: u64) -> Option<NormalizedL2Block> {
        let block = self.l2_blocks.get_mut(&timestamp)?.pop_front();
        if self.l2_blocks.get(&timestamp).is_some_and(VecDeque::is_empty) {
            self.l2_blocks.remove(&timestamp);
        }
        block
    }
}

#[cfg(test)]
mod tests {
    use alloy_eips::eip1898::BlockNumHash;
    use alloy_primitives::{B256, Bytes};
    use alloy_rlp::Encodable;
    use base_common_genesis::{ChainGenesis, RollupConfig};
    use base_protocol::{Batch, SingleBatch};

    use super::*;

    fn test_rollup_config() -> RollupConfig {
        RollupConfig {
            genesis: ChainGenesis {
                l2: BlockNumHash { number: 100, hash: B256::ZERO },
                ..Default::default()
            },
            block_time: 2,
            channel_timeout: 5,
            ..Default::default()
        }
    }

    fn encode_single_batch(batch: &SingleBatch) -> Vec<u8> {
        let typed_batch = Batch::Single(batch.clone());
        let mut batch_bytes = Vec::new();
        typed_batch.encode(&mut batch_bytes).expect("batch must encode");

        let mut rlp_buf = Vec::new();
        batch_bytes.as_slice().encode(&mut rlp_buf);
        miniz_oxide::deflate::compress_to_vec_zlib(&rlp_buf, 6)
    }

    fn single_frame(id: ChannelId, data: Vec<u8>) -> Frame {
        Frame { id, number: 0, data, is_last: true }
    }

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

    fn normalized_l2_block(
        timestamp: u64,
        epoch_num: u64,
        txs: &[&'static [u8]],
    ) -> NormalizedL2Block {
        NormalizedL2Block {
            timestamp,
            epoch_num,
            tx_hashes: txs.iter().map(|tx| alloy_primitives::keccak256(*tx)).collect(),
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

    #[test]
    fn pending_batch_delta_reports_queue_drift() {
        let mut state = ParityState::default();
        state.canonical.batches.push_back(normalized_batch(100));
        state.canonical.batches.push_back(normalized_batch(102));

        assert_eq!(state.pending_batch_delta(), 2);
    }

    #[test]
    fn compare_ready_matches_l2_blocks_independent_of_batch_position() {
        let mut state = ParityState::default();
        state.shadow.push_l2_block(normalized_l2_block(98, 9, &[b"shadow-extra"]));
        state.canonical.push_l2_block(normalized_l2_block(100, 10, &[b"tx-a"]));
        state.shadow.push_l2_block(normalized_l2_block(100, 10, &[b"tx-a"]));

        let stats = state.compare_ready(50);

        assert_eq!(stats.l2_block_matches, 1);
        assert_eq!(stats.l2_block_mismatches, 0);
        assert_eq!(state.canonical.pending_l2_blocks(), 0);
        assert_eq!(state.shadow.pending_l2_blocks(), 1);
        assert_eq!(state.shadow.oldest_l2_timestamp(), Some(98));
        assert_eq!(state.is_aligned(), Some(false));
    }

    #[test]
    fn compare_ready_records_l2_origin_mismatch() {
        let mut state = ParityState::default();
        state.canonical.push_l2_block(normalized_l2_block(100, 10, &[b"tx-a"]));
        state.shadow.push_l2_block(normalized_l2_block(100, 11, &[b"tx-a"]));

        let stats = state.compare_ready(50);

        assert_eq!(stats.l2_block_matches, 0);
        assert_eq!(stats.l2_block_mismatches, 1);
        assert_eq!(state.canonical.pending_l2_blocks(), 0);
        assert_eq!(state.shadow.pending_l2_blocks(), 0);
        assert_eq!(state.is_aligned(), Some(false));
    }

    #[test]
    fn compare_ready_records_l2_tx_count_mismatch() {
        let mut state = ParityState::default();
        state.canonical.push_l2_block(normalized_l2_block(100, 10, &[b"tx-a"]));
        state.shadow.push_l2_block(normalized_l2_block(100, 10, &[b"tx-a", b"tx-b"]));

        let stats = state.compare_ready(50);

        assert_eq!(stats.l2_block_matches, 0);
        assert_eq!(stats.l2_block_mismatches, 1);
        assert_eq!(state.is_aligned(), Some(false));
    }

    #[test]
    fn compare_ready_records_l2_tx_hash_mismatch() {
        let mut state = ParityState::default();
        state.canonical.push_l2_block(normalized_l2_block(100, 10, &[b"tx-a"]));
        state.shadow.push_l2_block(normalized_l2_block(100, 10, &[b"tx-b"]));

        let stats = state.compare_ready(50);

        assert_eq!(stats.l2_block_matches, 0);
        assert_eq!(stats.l2_block_mismatches, 1);
        assert_eq!(state.is_aligned(), Some(false));
    }

    #[test]
    fn pending_l2_blocks_counts_duplicate_timestamps() {
        let mut state = ParitySideState::default();
        state.push_l2_block(normalized_l2_block(100, 10, &[b"tx-a"]));
        state.push_l2_block(normalized_l2_block(100, 10, &[b"tx-a"]));

        assert_eq!(state.pending_l2_blocks(), 2);
        assert_eq!(state.oldest_l2_timestamp(), Some(100));
    }

    #[test]
    fn drain_ready_channels_skips_corrupt_channel_and_continues() {
        let rollup_config = test_rollup_config();
        let mut state = ParitySideState::default();
        let block_info = BlockInfo::default();
        let corrupt_id = [1u8; Channel::ID_LENGTH];
        let valid_id = [2u8; Channel::ID_LENGTH];
        let batch = SingleBatch {
            epoch_num: 123,
            timestamp: 1000,
            transactions: vec![Bytes::from_static(b"tx-a")],
            ..Default::default()
        };

        state.ingest_frame(single_frame(corrupt_id, vec![0x02]), block_info);
        state.ingest_frame(single_frame(valid_id, encode_single_batch(&batch)), block_info);

        let ingested = state.drain_ready_channels(0, &rollup_config);

        assert_eq!(ingested.complete_channels, 1);
        assert_eq!(ingested.batches, 1);
        assert_eq!(ingested.l2_blocks, 1);
        assert_eq!(ingested.decode_errors, 1);
        assert_eq!(state.pending_batches(), 1);
        assert_eq!(state.pending_l2_blocks(), 1);
        assert!(state.channels.is_empty());
        assert!(state.channel_order.is_empty());
    }

    #[test]
    fn evict_expired_channels_removes_stale_incomplete_channels() {
        let rollup_config = test_rollup_config();
        let mut state = ParitySideState::default();
        let block_info = BlockInfo { number: 10, ..Default::default() };
        let expired_id = [1u8; Channel::ID_LENGTH];
        let live_id = [2u8; Channel::ID_LENGTH];

        state.ingest_frame(
            Frame { id: expired_id, number: 0, data: vec![0x01], is_last: false },
            block_info,
        );
        state.ingest_frame(
            Frame { id: live_id, number: 0, data: vec![0x01], is_last: false },
            BlockInfo { number: 14, ..Default::default() },
        );

        let evicted = state.evict_expired_channels(16, 0, &rollup_config);

        assert_eq!(evicted, 1);
        assert!(!state.channels.contains_key(&expired_id));
        assert!(state.channels.contains_key(&live_id));
        assert_eq!(state.channel_order.iter().copied().collect::<Vec<_>>(), vec![live_id]);
    }
}
