//! CLI definition for the ZK prover host worker binary.

use std::{fmt, sync::Arc, time::Duration};

use base_cli_utils::{LogConfig, RuntimeManager};
use base_proof_succinct_host_utils::fetcher::{OPSuccinctDataFetcher, RPCConfig};
use base_proof_succinct_proof_utils::{ClusterArtifactStore, ClusterProofConfig};
use base_proof_worker::{
    DEFAULT_JOB_DISCOVERY_LOCK_DURATION_SECONDS, DEFAULT_JOB_DISCOVERY_MAX_CONCURRENT_JOBS,
    JobDiscovery, JobDiscoveryConfig, ProofSubmitter, ZkProofClaimType,
};
use base_proof_zk_backend::{
    ClusterZkProver, ClusterZkProverConfig, DryRunZkProver, MockZkProver, NetworkZkProver,
    NetworkZkProverConfig, OpSuccinctWitnessProvider,
};
use base_proof_zk_host::{
    DEFAULT_PROOF_GENERATOR_HEARTBEAT_LOCK_DURATION_SECONDS,
    DEFAULT_PROOF_GENERATOR_MAX_CONSECUTIVE_HEARTBEAT_FAILURES, ProofGenerator,
    ProofGeneratorHeartbeatConfig, ZkProver,
};
use base_prover_service_client::{ProverServiceClientConfig, ProverWorkerClient};
use base_prover_service_protocol::ZkVm;
use clap::{Parser, ValueEnum};
use eyre::eyre;
use sp1_cluster_common::client::ClusterServiceClient;
use sp1_sdk::network::{NetworkMode, signer::NetworkSigner};
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
    #[arg(long, env = "BASE_CONSENSUS_ADDRESS")]
    base_consensus_address: Option<String>,

    /// L1 execution node RPC URL. Required for `ZK_BACKEND=cluster` or `network`.
    #[arg(long, env = "L1_NODE_ADDRESS")]
    l1_node_address: Option<String>,

    /// L1 beacon node RPC URL. Required for `ZK_BACKEND=cluster` or `network`.
    #[arg(long, env = "L1_BEACON_ADDRESS")]
    l1_beacon_address: Option<String>,

    /// L2 execution node RPC URL. Required for `ZK_BACKEND=cluster` or `network`.
    #[arg(long, env = "L2_NODE_ADDRESS")]
    l2_node_address: Option<String>,

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
    #[arg(long, env = "NETWORK_PRIVATE_KEY")]
    network_private_key: Option<String>,

    /// SP1 network fulfillment strategy: `reserved`, `hosted`, or `auction`.
    #[arg(long, env = "SP1_FULFILLMENT_STRATEGY", default_value = "auction")]
    sp1_fulfillment_strategy: String,

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

struct RequiredRpcArgs<'a> {
    base_consensus_url: &'a str,
    l1_node_url: &'a str,
    l1_beacon_url: &'a str,
    l2_node_url: &'a str,
}

struct ClusterArtifactStoreConfig {
    store: ClusterArtifactStore,
    request_config: sp1_cluster_utils::ArtifactStoreConfig,
}

impl<'a> TryFrom<&'a WorkerArgs> for RequiredRpcArgs<'a> {
    type Error = eyre::Report;

    fn try_from(args: &'a WorkerArgs) -> Result<Self, Self::Error> {
        Ok(Self {
            base_consensus_url: args.base_consensus_address.as_deref().ok_or_else(|| {
                eyre!("BASE_CONSENSUS_ADDRESS must be set for the selected ZK_BACKEND")
            })?,
            l1_node_url: args
                .l1_node_address
                .as_deref()
                .ok_or_else(|| eyre!("L1_NODE_ADDRESS must be set for the selected ZK_BACKEND"))?,
            l1_beacon_url: args.l1_beacon_address.as_deref().ok_or_else(|| {
                eyre!("L1_BEACON_ADDRESS must be set for the selected ZK_BACKEND")
            })?,
            l2_node_url: args
                .l2_node_address
                .as_deref()
                .ok_or_else(|| eyre!("L2_NODE_ADDRESS must be set for the selected ZK_BACKEND"))?,
        })
    }
}

impl TryFrom<&RequiredRpcArgs<'_>> for RPCConfig {
    type Error = eyre::Report;

    fn try_from(args: &RequiredRpcArgs<'_>) -> Result<Self, Self::Error> {
        Ok(Self {
            l1_rpc: Url::parse(args.l1_node_url).map_err(|e| eyre!("invalid L1 RPC URL: {e}"))?,
            l1_beacon_rpc: Some(
                Url::parse(args.l1_beacon_url).map_err(|e| eyre!("invalid beacon RPC URL: {e}"))?,
            ),
            l2_rpc: Url::parse(args.l2_node_url).map_err(|e| eyre!("invalid L2 RPC URL: {e}"))?,
            l2_node_rpc: Url::parse(args.base_consensus_url)
                .map_err(|e| eyre!("invalid Base consensus RPC URL: {e}"))?,
        })
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
        let prover = self.build_backend().await?;

        let client_config = ProverServiceClientConfig::new(args.prover_service_endpoint.clone())
            .with_request_timeout(Duration::from_secs(args.prover_service_request_timeout_secs));
        let client = ProverWorkerClient::connect(&client_config)
            .map_err(|e| eyre!("failed to connect to prover service: {e}"))?;

        let submitter = ProofSubmitter::new(client.clone());
        let heartbeat = ProofGeneratorHeartbeatConfig::with_max_consecutive_failures(
            Duration::from_secs(args.proof_generator_heartbeat_interval_secs),
            args.proof_generator_heartbeat_lock_duration_seconds,
            args.proof_generator_max_consecutive_heartbeat_failures,
        );
        let proof_generator = Arc::new(ProofGenerator::new(prover, submitter, heartbeat));

        let worker_id = format!("zk-host-{}", Uuid::new_v4());
        let discovery_config =
            JobDiscoveryConfig::zk(worker_id.clone(), proof_type, vec![ZkVm::Sp1])
                .with_poll_interval(Duration::from_millis(args.job_discovery_poll_interval_ms))
                .with_lock_duration_seconds(args.job_discovery_lock_duration_seconds)
                .with_max_concurrent_jobs(args.job_discovery_max_concurrent_jobs);
        let discovery = JobDiscovery::new(client, proof_generator, discovery_config);

        info!(
            worker_id = %worker_id,
            prover_service_endpoint = %args.prover_service_endpoint,
            proof_type = ?proof_type,
            backend = %args.backend,
            "starting zk prover host worker"
        );
        discovery.run_until_cancelled(cancel).await;
        Ok(())
    }

    /// Selects the [`ZkProver`] backend implementation from CLI/env settings.
    async fn build_backend(&self) -> eyre::Result<Arc<dyn ZkProver>> {
        match self.args.backend {
            ZkBackendArg::Mock => Ok(Arc::new(MockZkProver)),
            ZkBackendArg::DryRun => Ok(Arc::new(DryRunZkProver)),
            ZkBackendArg::Cluster => self.build_cluster_backend().await,
            ZkBackendArg::Network => self.build_network_backend().await,
        }
    }

    async fn build_cluster_backend(&self) -> eyre::Result<Arc<dyn ZkProver>> {
        let args = &self.args;
        let rpc_args = RequiredRpcArgs::try_from(args)?;
        let cluster_rpc = args.sp1_cluster_api_endpoint.as_deref().ok_or_else(|| {
            eyre!("SP1_CLUSTER_API_ENDPOINT must be set for the selected ZK_BACKEND")
        })?;

        info!("ZK_BACKEND=cluster: using Succinct SP1 cluster backend");
        let provider = self.build_witness_provider(&rpc_args).await?;
        let artifact_store = self.cluster_artifact_store().await?;
        let service_client = ClusterServiceClient::new(cluster_rpc.to_owned())
            .await
            .map_err(|e| eyre!("failed to create SP1 cluster client: {e}"))?;
        let timeout_secs = args
            .sp1_cluster_timeout_hours
            .checked_mul(3600)
            .ok_or_else(|| eyre!("SP1_CLUSTER_TIMEOUT_HOURS is too large"))?;
        let config = ClusterZkProverConfig {
            base_consensus_url: rpc_args.base_consensus_url.to_owned(),
            l1_node_url: rpc_args.l1_node_url.to_owned(),
            default_sequence_window: args.default_sequence_window,
            cluster: Arc::new(ClusterProofConfig {
                cluster_rpc: cluster_rpc.to_owned(),
                artifact_store: artifact_store.store,
                artifact_store_config: artifact_store.request_config,
                service_client,
            }),
            timeout: Duration::from_secs(timeout_secs),
            range_cycle_limit: args.range_cycle_limit,
            range_gas_limit: args.range_gas_limit,
        };

        Ok(Arc::new(ClusterZkProver::new(provider, config)))
    }

    async fn build_network_backend(&self) -> eyre::Result<Arc<dyn ZkProver>> {
        let args = &self.args;
        let rpc_args = RequiredRpcArgs::try_from(args)?;

        info!("ZK_BACKEND=network: using Succinct SP1 Network backend");
        info!("computing range proving key");
        let (range_pk, _range_vk, _agg_pk, _agg_vk) =
            base_proof_succinct_proof_utils::cluster_setup_keys()
                .await
                .map_err(|e| eyre!("failed to compute proving keys: {e}"))?;
        info!("range proving key computed successfully");

        let provider = self.build_witness_provider(&rpc_args).await?;

        let fulfillment_strategy =
            base_proof_succinct_host_utils::network::parse_fulfillment_strategy(
                args.sp1_fulfillment_strategy.clone(),
            )
            .map_err(|e| eyre!("invalid fulfillment strategy: {e}"))?;
        let network_mode = match fulfillment_strategy {
            sp1_sdk::network::FulfillmentStrategy::Auction => NetworkMode::Mainnet,
            _ => NetworkMode::Reserved,
        };
        let network_signer = self.network_signer().await?;

        info!(
            network_mode = ?network_mode,
            fulfillment_strategy = ?fulfillment_strategy,
            "creating SP1 Network prover"
        );
        let network_prover = Arc::new(
            sp1_sdk::ProverClient::builder()
                .network_for(network_mode)
                .signer(network_signer)
                .build()
                .await,
        );

        let timeout_secs = args
            .sp1_network_timeout_hours
            .checked_mul(3600)
            .ok_or_else(|| eyre!("SP1_NETWORK_TIMEOUT_HOURS is too large"))?;
        let config = NetworkZkProverConfig {
            base_consensus_url: rpc_args.base_consensus_url.to_owned(),
            l1_node_url: rpc_args.l1_node_url.to_owned(),
            default_sequence_window: args.default_sequence_window,
            network_prover,
            range_pk: range_pk.into(),
            fulfillment_strategy,
            timeout: Duration::from_secs(timeout_secs),
            range_cycle_limit: args.range_cycle_limit,
            range_gas_limit: args.range_gas_limit,
        };

        Ok(Arc::new(NetworkZkProver::new(provider, config)))
    }

    async fn build_witness_provider(
        &self,
        rpc_args: &RequiredRpcArgs<'_>,
    ) -> eyre::Result<OpSuccinctWitnessProvider> {
        let rpc_config = RPCConfig::try_from(rpc_args)?;
        let fetcher = Arc::new(
            OPSuccinctDataFetcher::from_rpc_config_with_rollup_config(rpc_config)
                .await
                .map_err(|e| eyre!("failed to create OPSuccinctDataFetcher: {e}"))?,
        );

        Ok(OpSuccinctWitnessProvider::new(fetcher))
    }

    async fn cluster_artifact_store(&self) -> eyre::Result<ClusterArtifactStoreConfig> {
        let args = &self.args;
        let bucket = args
            .cli_s3_bucket
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| eyre!("CLI_S3_BUCKET is required for ZK_BACKEND=cluster"))?
            .to_owned();
        let region = args
            .cli_s3_region
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| eyre!("CLI_S3_REGION is required for ZK_BACKEND=cluster"))?
            .to_owned();

        info!("using S3 artifact storage");
        let client = sp1_cluster_artifact::s3::S3ArtifactClient::new(
            region.clone(),
            bucket.clone(),
            32,
            sp1_cluster_artifact::s3::S3DownloadMode::AwsSDK(
                sp1_cluster_artifact::s3::S3ArtifactClient::create_s3_sdk_download_client(
                    region.clone(),
                )
                .await,
            ),
        )
        .await;

        Ok(ClusterArtifactStoreConfig {
            store: ClusterArtifactStore::S3(client),
            request_config: sp1_cluster_utils::ArtifactStoreConfig::S3 { bucket, region },
        })
    }

    async fn network_signer(&self) -> eyre::Result<NetworkSigner> {
        let args = &self.args;
        let key = args
            .network_private_key
            .as_deref()
            .ok_or_else(|| eyre!("NETWORK_PRIVATE_KEY must be set for the selected ZK_BACKEND"))?;

        if args.use_kms_requester {
            NetworkSigner::aws_kms(key)
                .await
                .map_err(|e| eyre!("failed to create KMS network signer: {e}"))
        } else {
            NetworkSigner::local(key)
                .map_err(|e| eyre!("failed to create local network signer: {e}"))
        }
    }
}
