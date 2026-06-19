# base-proof-zk-host

Host-side ZK proving worker for the prover service.

This crate adapts the shared worker machinery for ZK proving jobs. It provides
[`ProofGenerator`], which drives a [`ZkProver`] backend to completion for one
claimed ZK job, and [`ZkHost`], which wires the proof generator into the
shared prover-service discovery loop.

The concrete SP1 backend is wired separately. [`UnimplementedZkProver`] is a
placeholder for early host wiring.

[`ProofGenerator`]: crate::ProofGenerator
[`ZkHost`]: crate::ZkHost
[`ZkProver`]: crate::ZkProver
[`UnimplementedZkProver`]: crate::UnimplementedZkProver
