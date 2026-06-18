//! Batcher service metric definitions.

base_metrics::define_metrics! {
    batcher.shadow_parity, struct = BatcherServiceMetrics,
    #[describe("Whether the shadow parity monitor is running")]
    enabled: gauge,
    #[describe("Latest L1 block processed by the shadow parity monitor")]
    latest_l1_block: gauge,
    #[describe("Total canonical batch inbox payloads observed by the shadow parity monitor")]
    canonical_payloads_total: counter,
    #[describe("Total shadow batch inbox payloads observed by the shadow parity monitor")]
    shadow_payloads_total: counter,
    #[describe("Total canonical complete channels decoded by the shadow parity monitor")]
    canonical_complete_channels_total: counter,
    #[describe("Total shadow complete channels decoded by the shadow parity monitor")]
    shadow_complete_channels_total: counter,
    #[describe("Total canonical batches decoded by the shadow parity monitor")]
    canonical_batches_total: counter,
    #[describe("Total shadow batches decoded by the shadow parity monitor")]
    shadow_batches_total: counter,
    #[describe("Canonical decoded batches waiting for a shadow comparison")]
    canonical_pending_batches: gauge,
    #[describe("Shadow decoded batches waiting for a canonical comparison")]
    shadow_pending_batches: gauge,
    #[describe("Absolute decoded-batch queue length difference between canonical and shadow")]
    pending_batch_delta: gauge,
    #[describe("Total matching batch parity comparisons")]
    matches_total: counter,
    #[describe("Total diverging batch parity comparisons")]
    divergences_total: counter,
    #[describe("Latest shadow parity alignment state: 1 for aligned, 0 for divergence or lag")]
    aligned: gauge,
    #[describe("Latest L1 block where a matching shadow parity comparison was observed")]
    #[no_zero]
    last_match_l1_block: gauge,
    #[describe("Latest L1 block where a shadow parity divergence was observed")]
    #[no_zero]
    last_divergence_l1_block: gauge,
    #[describe("Total L1 fetch errors seen by the shadow parity monitor")]
    l1_fetch_errors_total: counter,
    #[describe("Total blob sidecar fetch errors seen by the shadow parity monitor")]
    blob_fetch_errors_total: counter,
    #[describe("Total payload/frame/channel extraction errors seen by the shadow parity monitor")]
    extraction_errors_total: counter,
    #[describe("Total incomplete channels evicted by the shadow parity monitor")]
    evicted_channels_total: counter,
    #[describe("Total blob submissions skipped because no L1 beacon URL is configured")]
    missing_beacon_total: counter,
}
