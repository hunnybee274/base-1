# `base-batcher-parity`

Normalized parity helpers for comparing batch submissions produced by different
batchers.

Raw calldata and blob payloads include volatile frame metadata, most notably the
channel ID, so byte-for-byte comparisons can report false mismatches even when
the derived L2 batches are identical. This crate decodes submissions through the
same frame, channel, blob, and batch codecs used by the Base node and returns a
stable summary of each decoded batch: kind, timestamps, L1 origin numbers,
per-block transaction counts, and transaction hashes.

The intended rollout use is:

- normalize the canonical `op-batcher` submission;
- normalize the shadow `base-batcher` submission;
- compare the normalized batches and alert on mismatches, incomplete channels,
  rejected frames, or decode failures.

This crate intentionally does not decide verifier-node policy. A stock
`base-consensus` verifier filters DA by both `RollupConfig.batch_inbox_address`
and the current `SystemConfig.batcher_address`. A shadow batcher using a unique
signer and a shadow inbox can prove normalized DA parity, but it will not feed a
stock verifier unless the verifier's accepted inbox and signer match those
submissions. Full safe-chain equality therefore requires deploying the shadow
writer against accepted derivation inputs or using an explicitly isolated
verifier-only configuration; production consensus should not grow permanent
shadow bypass logic for this rollout.
