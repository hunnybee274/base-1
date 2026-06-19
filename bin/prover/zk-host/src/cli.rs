//! CLI definition for the ZK prover host worker binary.

use std::{fmt, time::Duration};

use base_cli_utils::{LogConfig, RuntimeManager};
use base_proof_worker::{
    DEFAULT_JOB_DISCOVERY_LOCK_DURATION_SECONDS, DEFAULT_JOB_DISCOVERY_MAX_CONCURRENT_JOBS,
    ZkProofClaimType,
};
use base_proof_zk_backend::{
    SuccinctBackendBuilder, SuccinctBackendKind, SuccinctClusterBackendConfig,
    SuccinctNetworkBackendConfig, SuccinctNetworkFulfillmentStrategy, SuccinctNetworkRequester,
};
use base_proof_zk_host::{
    DEFAULT_PROOF_GENERATOR_HEARTBEAT_LOCK_DURATION_SECONDS,
    DEFAULT_PROOF_GENERATOR_MAX_CONSECUTIVE_HEARTBEAT_FAILURES, ProofGeneratorHeartbeatConfig,
    ZkHost, ZkHostConfig,
};
use base_prover_service_client::{ProverServiceClientConfig, ProverWorkerClient};
use base_prover_service_protocol::ZkVm;
use clap::{Parser, ValueEnum};
use eyre::{WrapErr, eyre};
use tokio_util::sync::CancellationToken;
use tracing::info;
use url::Url;
use uuid::Uuid;

base_cli_utils::define_log_args!("BASE_PROVER_ZK_HOST");
base_cli_utils::define_metrics_args!("BASE_PROVER_ZK_HOST", 7303);

/// ZK prover host worker binary.
#[derive(Parser)]
#[command(author, version)]
pub(crate) struct Cli {
    #[command(flatten)]
    worker: WorkerArgs,

    /// Logging arguments.
    #[command(flatten)]
    logging: LogArgs,

    /// Metrics arguments.
    #[command(flatten)]
    metrics: MetricsArgs,
}

/// Worker-mode arguments for claiming and generating ZK proof jobs.
#[derive(Parser)]
struct WorkerArgs {
    /// Prover-service JSON-RPC endpoint.
    #[arg(long, env = "PROVER_SERVICE_ENDPOINT")]
    prover_service_endpoint: String,

    /// Prover-service JSON-RPC request timeout in seconds.
    #[arg(long, env = "PROVER_SERVICE_REQUEST_TIMEOUT_SECS", default_value_t = 60)]
    prover_service_request_timeout_secs: u64,

    /// ZK proof type to claim: `compressed` or `snark_groth16`.
    #[arg(long, env = "PROOF_TYPE", value_enum, default_value = "compressed")]
    proof_type: ZkProofTypeArg,

    /// Proving backend to run: `mock`, `dry_run`, `cluster`, or `network`.
    #[arg(long, env = "ZK_BACKEND", value_enum, default_value = "mock")]
    backend: ZkBackendArg,

    /// Base consensus node RPC URL. Required for `ZK_BACKEND=cluster` or `network`.
    #[arg(
        long,
        env = "BASE_CONSENSUS_ADDRESS",
        required_if_eq_any([("backend", "cluster"), ("backend", "network")])
    )]
    base_consensus_address: Option<Url>,

    /// L1 execution node RPC URL. Required for `ZK_BACKEND=cluster` or `network`.
    #[arg(
        long,
        env = "L1_NODE_ADDRESS",
        required_if_eq_any([("backend", "cluster"), ("backend", "network")])
    )]
    l1_node_address: Option<Url>,

    /// L1 beacon node RPC URL. Required for `ZK_BACKEND=cluster` or `network`.
    #[arg(
        long,
        env = "L1_BEACON_ADDRESS",
        required_if_eq_any([("backend", "cluster"), ("backend", "network")])
    )]
    l1_beacon_address: Option<Url>,

    /// L2 execution node RPC URL. Required for `ZK_BACKEND=cluster` or `network`.
    #[arg(
        long,
        env = "L2_NODE_ADDRESS",
        required_if_eq_any([("backend", "cluster"), ("backend", "network")])
    )]
    l2_node_address: Option<Url>,

    /// Default sequence window for L1 head calculations.
    #[arg(long, env = "DEFAULT_SEQUENCE_WINDOW", default_value_t = 50)]
    default_sequence_window: u64,

    /// SP1 cluster gRPC endpoint. Required for `ZK_BACKEND=cluster`.
    #[arg(long, env = "SP1_CLUSTER_API_ENDPOINT")]
    sp1_cluster_api_endpoint: Option<String>,

    /// SP1 cluster proof timeout in hours.
    #[arg(long, env = "SP1_CLUSTER_TIMEOUT_HOURS", default_value_t = 24)]
    sp1_cluster_timeout_hours: u64,

    /// S3 artifact store bucket for `ZK_BACKEND=cluster`.
    #[arg(long, env = "CLI_S3_BUCKET")]
    cli_s3_bucket: Option<String>,

    /// S3 artifact store region for `ZK_BACKEND=cluster`.
    #[arg(long, env = "CLI_S3_REGION")]
    cli_s3_region: Option<String>,

    /// SP1 network requester private key, or KMS key ARN when `USE_KMS_REQUESTER=true`.
    #[arg(long, env = "NETWORK_PRIVATE_KEY", hide_env_values = true)]
    network_private_key: Option<String>,

    /// SP1 network fulfillment strategy: `reserved`, `hosted`, or `auction`.
    #[arg(long, env = "SP1_FULFILLMENT_STRATEGY", value_enum, default_value = "auction")]
    sp1_fulfillment_strategy: Sp1FulfillmentStrategyArg,

    /// Use the requester key as an AWS KMS ARN instead of a local private key.
    #[arg(long, env = "USE_KMS_REQUESTER", default_value_t = false)]
    use_kms_requester: bool,

    /// SP1 network proof timeout in hours.
    #[arg(long, env = "SP1_NETWORK_TIMEOUT_HOURS", default_value_t = 24)]
    sp1_network_timeout_hours: u64,

    /// Cycle limit for range proof requests.
    #[arg(long, env = "RANGE_CYCLE_LIMIT", default_value_t = 1_000_000_000_000)]
    range_cycle_limit: u64,

    /// Gas limit for range proof requests.
    #[arg(long, env = "RANGE_GAS_LIMIT", default_value_t = 1_000_000_000_000)]
    range_gas_limit: u64,

    /// Delay after an empty or failed discovery attempt, in milliseconds.
    #[arg(long, env = "JOB_DISCOVERY_POLL_INTERVAL_MS", default_value_t = 5_000)]
    job_discovery_poll_interval_ms: u64,

    /// Requested claim lock duration in seconds. Zero uses the server default.
    #[arg(
        long,
        env = "JOB_DISCOVERY_LOCK_DURATION_SECONDS",
        default_value_t = DEFAULT_JOB_DISCOVERY_LOCK_DURATION_SECONDS
    )]
    job_discovery_lock_duration_seconds: u32,

    /// Maximum number of claimed proof jobs generated concurrently.
    #[arg(
        long,
        env = "JOB_DISCOVERY_MAX_CONCURRENT_JOBS",
        default_value_t = DEFAULT_JOB_DISCOVERY_MAX_CONCURRENT_JOBS
    )]
    job_discovery_max_concurrent_jobs: usize,

    /// Delay between worker API heartbeats while a proof is being generated.
    #[arg(long, env = "PROOF_GENERATOR_HEARTBEAT_INTERVAL_SECS", default_value_t = 30)]
    proof_generator_heartbeat_interval_secs: u64,

    /// Requested heartbeat lock duration in seconds. Zero uses the server default.
    #[arg(
        long,
        env = "PROOF_GENERATOR_HEARTBEAT_LOCK_DURATION_SECONDS",
        default_value_t = DEFAULT_PROOF_GENERATOR_HEARTBEAT_LOCK_DURATION_SECONDS
    )]
    proof_generator_heartbeat_lock_duration_seconds: u32,

    /// Maximum consecutive retryable heartbeat failures before aborting generation.
    #[arg(
        long,
        env = "PROOF_GENERATOR_MAX_CONSECUTIVE_HEARTBEAT_FAILURES",
        default_value_t = DEFAULT_PROOF_GENERATOR_MAX_CONSECUTIVE_HEARTBEAT_FAILURES
    )]
    proof_generator_max_consecutive_heartbeat_failures: u32,
}

struct Worker {
    args: WorkerArgs,
}

impl From<WorkerArgs> for Worker {
    fn from(args: WorkerArgs) -> Self {
        Self { args }
    }
}

/// ZK proof type argument.
#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum ZkProofTypeArg {
    /// Claim compressed ZK proofs.
    Compressed,
    /// Claim SNARK Groth16 proofs.
    #[value(alias = "snark_groth16", alias = "groth16")]
    SnarkGroth16,
}

impl From<ZkProofTypeArg> for ZkProofClaimType {
    fn from(proof_type: ZkProofTypeArg) -> Self {
        match proof_type {
            ZkProofTypeArg::Compressed => Self::Compressed,
            ZkProofTypeArg::SnarkGroth16 => Self::SnarkGroth16,
        }
    }
}

/// ZK proving backend argument.
#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum ZkBackendArg {
    /// Return placeholder proof bytes without an external backend.
    Mock,
    /// Return empty proof bytes without an external backend.
    #[value(alias = "dry_run", alias = "dryrun")]
    DryRun,
    /// Submit proofs to an SP1 cluster.
    Cluster,
    /// Submit proofs to the Succinct SP1 Network.
    Network,
}

impl AsRef<str> for ZkBackendArg {
    fn as_ref(&self) -> &str {
        match self {
            Self::Mock => "mock",
            Self::DryRun => "dry_run",
            Self::Cluster => "cluster",
            Self::Network => "network",
        }
    }
}

impl fmt::Display for ZkBackendArg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_ref())
    }
}

impl ZkBackendArg {
    const fn supports_proof_type(self, proof_type: ZkProofTypeArg) -> bool {
        match self {
            Self::Mock | Self::DryRun => true,
            Self::Cluster | Self::Network => matches!(proof_type, ZkProofTypeArg::Compressed),
        }
    }
}

impl From<ZkBackendArg> for SuccinctBackendKind {
    fn from(backend: ZkBackendArg) -> Self {
        match backend {
            ZkBackendArg::Mock => Self::Mock,
            ZkBackendArg::DryRun => Self::DryRun,
            ZkBackendArg::Cluster => Self::Cluster,
            ZkBackendArg::Network => Self::Network,
        }
    }
}

/// SP1 network fulfillment strategy argument.
#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum Sp1FulfillmentStrategyArg {
    /// Submit proofs to reserved SP1 Network capacity.
    Reserved,
    /// Submit proofs to hosted SP1 Network capacity.
    Hosted,
    /// Submit proofs to the SP1 Network auction.
    Auction,
}

impl From<Sp1FulfillmentStrategyArg> for SuccinctNetworkFulfillmentStrategy {
    fn from(strategy: Sp1FulfillmentStrategyArg) -> Self {
        match strategy {
            Sp1FulfillmentStrategyArg::Reserved => Self::Reserved,
            Sp1FulfillmentStrategyArg::Hosted => Self::Hosted,
            Sp1FulfillmentStrategyArg::Auction => Self::Auction,
        }
    }
}

impl Cli {
    /// Run the worker.
    pub(crate) fn run(self) -> eyre::Result<()> {
        let Self { worker, logging, metrics } = self;
        LogConfig::from(logging).init_tracing_subscriber()?;
        base_cli_utils::MetricsConfig::from(metrics).init_with(|| {
            base_cli_utils::register_version_metrics!();
        })?;

        let worker = Worker::from(worker);

        RuntimeManager::new()
            .with_thread_stack_size(8 * 1024 * 1024)
            .run_until_shutdown(|cancel| async move { worker.run(cancel).await })
    }
}

impl Worker {
    async fn run(self, cancel: CancellationToken) -> eyre::Result<()> {
        let args = &self.args;
        if !args.backend.supports_proof_type(args.proof_type) {
            return Err(eyre!(
                "ZK_BACKEND={} currently supports PROOF_TYPE=compressed only",
                args.backend
            ));
        }
        let proof_type = ZkProofClaimType::from(args.proof_type);
        info!(
            prover_service_endpoint = %args.prover_service_endpoint,
            proof_type = ?proof_type,
            backend = %args.backend,
            "initializing zk prover host worker"
        );
        let backend_builder = SuccinctBackendBuilder {
            backend: args.backend.into(),
            base_consensus_rpc: args.base_consensus_address.clone(),
            l1_rpc: args.l1_node_address.clone(),
            l1_beacon_rpc: args.l1_beacon_address.clone(),
            l2_rpc: args.l2_node_address.clone(),
            default_sequence_window: args.default_sequence_window,
            cluster: SuccinctClusterBackendConfig {
                cluster_rpc_endpoint: args.sp1_cluster_api_endpoint.clone(),
                s3_bucket: args.cli_s3_bucket.clone(),
                s3_region: args.cli_s3_region.clone(),
                timeout_hours: args.sp1_cluster_timeout_hours,
            },
            network: SuccinctNetworkBackendConfig {
                requester: args.network_private_key.as_ref().map(|key| {
                    if args.use_kms_requester {
                        SuccinctNetworkRequester::AwsKmsKeyId(key.clone())
                    } else {
                        SuccinctNetworkRequester::LocalPrivateKey(key.clone())
                    }
                }),
                fulfillment_strategy: args.sp1_fulfillment_strategy.into(),
                timeout_hours: args.sp1_network_timeout_hours,
            },
            range_cycle_limit: args.range_cycle_limit,
            range_gas_limit: args.range_gas_limit,
        };
        let Some(prover) =
            backend_builder.build(&cancel).await.wrap_err("failed to initialize ZK backend")?
        else {
            info!(
                proof_type = ?proof_type,
                backend = %args.backend,
                "zk prover host worker initialization cancelled"
            );
            return Ok(());
        };
        if cancel.is_cancelled() {
            info!(
                proof_type = ?proof_type,
                backend = %args.backend,
                "zk prover host worker startup cancelled"
            );
            return Ok(());
        }

        let client_config = ProverServiceClientConfig::new(args.prover_service_endpoint.clone())
            .with_request_timeout(Duration::from_secs(args.prover_service_request_timeout_secs));
        let client = ProverWorkerClient::connect(&client_config)
            .wrap_err("failed to connect to prover service")?;

        let heartbeat = ProofGeneratorHeartbeatConfig::with_max_consecutive_failures(
            Duration::from_secs(args.proof_generator_heartbeat_interval_secs),
            args.proof_generator_heartbeat_lock_duration_seconds,
            args.proof_generator_max_consecutive_heartbeat_failures,
        );

        let worker_id = format!("zk-host-{}", Uuid::new_v4());
        let host_config = ZkHostConfig::new(worker_id.clone(), proof_type, vec![ZkVm::Sp1])
            .with_job_discovery_poll_interval(Duration::from_millis(
                args.job_discovery_poll_interval_ms,
            ))
            .with_job_discovery_lock_duration_seconds(args.job_discovery_lock_duration_seconds)
            .with_job_discovery_max_concurrent_jobs(args.job_discovery_max_concurrent_jobs)
            .with_proof_generator_heartbeat(heartbeat);
        let host = ZkHost::new(client, prover, host_config);

        info!(
            worker_id = %worker_id,
            prover_service_endpoint = %args.prover_service_endpoint,
            proof_type = ?proof_type,
            backend = %args.backend,
            "starting zk prover host worker"
        );
        host.run_until_cancelled(cancel).await;
        Ok(())
    }
}
