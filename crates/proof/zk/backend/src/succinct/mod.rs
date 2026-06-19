//! SP1 (Succinct) ZK proving backends.
//!
//! Each backend implements [`base_proof_zk_host::ZkProver`] for a different SP1
//! execution target.

mod provider;
pub use provider::{L1HeadSource, OpSuccinctWitnessProvider, WitnessError, WitnessParams};

mod builder;
pub use builder::{
    SuccinctBackendBuildError, SuccinctBackendBuildResult, SuccinctBackendBuilder,
    SuccinctBackendKind, SuccinctClusterBackendConfig, SuccinctNetworkBackendConfig,
    SuccinctNetworkFulfillmentStrategy, SuccinctNetworkRequester,
};

mod backends;
pub use backends::{
    ClusterSessionId, ClusterZkProver, ClusterZkProverConfig, DRY_RUN_SNARK_PREFIX, DryRunZkProver,
    MOCK_PROOF_BYTES, MOCK_SNARK_PREFIX, MockZkProver, NetworkZkProver, NetworkZkProverConfig,
};
