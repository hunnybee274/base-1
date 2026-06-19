//! Construction helpers for Succinct ZK proving backends.

use std::{error::Error as StdError, fmt, future::Future, pin::Pin, sync::Arc, time::Duration};

use base_proof_succinct_host_utils::fetcher::{OPSuccinctDataFetcher, RPCConfig};
use base_proof_succinct_proof_utils::{ClusterArtifactStore, ClusterProofConfig};
use base_proof_zk_host::ZkProver;
use sp1_cluster_common::client::ClusterServiceClient;
use sp1_sdk::network::{FulfillmentStrategy, NetworkMode, signer::NetworkSigner};
use thiserror::Error;
use tokio_util::sync::CancellationToken;
use tracing::info;
use url::Url;

use crate::succinct::{
    ClusterZkProver, ClusterZkProverConfig, DryRunZkProver, MockZkProver, NetworkZkProver,
    NetworkZkProverConfig, OpSuccinctWitnessProvider,
};

/// Result type for Succinct backend construction.
pub type SuccinctBackendBuildResult<T> = Result<T, SuccinctBackendBuildError>;

/// Selects which Succinct backend to construct.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SuccinctBackendKind {
    /// Return placeholder proof bytes without an external backend.
    Mock,
    /// Return empty proof bytes without an external backend.
    DryRun,
    /// Submit proofs to an SP1 cluster.
    Cluster,
    /// Submit proofs to the Succinct SP1 Network.
    Network,
}

impl fmt::Display for SuccinctBackendKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Mock => f.write_str("mock"),
            Self::DryRun => f.write_str("dry_run"),
            Self::Cluster => f.write_str("cluster"),
            Self::Network => f.write_str("network"),
        }
    }
}

/// Fulfillment mode for Succinct SP1 Network proof requests.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SuccinctNetworkFulfillmentStrategy {
    /// Submit proofs to reserved SP1 Network capacity.
    Reserved,
    /// Submit proofs to hosted SP1 Network capacity.
    Hosted,
    /// Submit proofs to the SP1 Network auction.
    Auction,
}

impl From<SuccinctNetworkFulfillmentStrategy> for FulfillmentStrategy {
    fn from(strategy: SuccinctNetworkFulfillmentStrategy) -> Self {
        match strategy {
            SuccinctNetworkFulfillmentStrategy::Reserved => Self::Reserved,
            SuccinctNetworkFulfillmentStrategy::Hosted => Self::Hosted,
            SuccinctNetworkFulfillmentStrategy::Auction => Self::Auction,
        }
    }
}

/// Requester credential source for Succinct SP1 Network proof requests.
#[derive(Clone, Eq, PartialEq)]
pub enum SuccinctNetworkRequester {
    /// Use a local private key.
    LocalPrivateKey(String),
    /// Load the requester key from AWS KMS.
    AwsKmsKeyId(String),
}

impl fmt::Debug for SuccinctNetworkRequester {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LocalPrivateKey(_) => f.write_str("LocalPrivateKey(<redacted>)"),
            Self::AwsKmsKeyId(_) => f.write_str("AwsKmsKeyId(<redacted>)"),
        }
    }
}

/// SP1 cluster backend construction settings.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SuccinctClusterBackendConfig {
    /// SP1 cluster gRPC endpoint.
    pub cluster_rpc_endpoint: Option<String>,
    /// S3 artifact store bucket.
    pub s3_bucket: Option<String>,
    /// S3 artifact store region.
    pub s3_region: Option<String>,
    /// SP1 cluster proof timeout in hours.
    pub timeout_hours: u64,
}

/// SP1 Network backend construction settings.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SuccinctNetworkBackendConfig {
    /// Requester credential source.
    pub requester: Option<SuccinctNetworkRequester>,
    /// Fulfillment strategy for range proof requests.
    pub fulfillment_strategy: SuccinctNetworkFulfillmentStrategy,
    /// SP1 network proof timeout in hours.
    pub timeout_hours: u64,
}

/// Settings used to construct a concrete Succinct backend.
#[derive(Clone, Debug)]
pub struct SuccinctBackendBuilder {
    /// Backend implementation to construct.
    pub backend: SuccinctBackendKind,
    /// Base consensus node RPC URL.
    pub base_consensus_rpc: Option<Url>,
    /// L1 execution node RPC URL.
    pub l1_rpc: Option<Url>,
    /// L1 beacon node RPC URL.
    pub l1_beacon_rpc: Option<Url>,
    /// L2 execution node RPC URL.
    pub l2_rpc: Option<Url>,
    /// Default sequence window for L1 head calculations.
    pub default_sequence_window: u64,
    /// Cluster backend settings.
    pub cluster: SuccinctClusterBackendConfig,
    /// Network backend settings.
    pub network: SuccinctNetworkBackendConfig,
    /// Cycle limit for range proof requests.
    pub range_cycle_limit: u64,
    /// Gas limit for range proof requests.
    pub range_gas_limit: u64,
}

/// Errors raised while constructing a Succinct backend.
#[derive(Debug, Error)]
pub enum SuccinctBackendBuildError {
    /// A selected backend is missing a required configuration value.
    #[error("{field} must be set for ZK_BACKEND={backend}")]
    MissingConfig {
        /// Selected backend.
        backend: SuccinctBackendKind,
        /// Missing field name.
        field: &'static str,
    },
    /// A timeout value overflowed seconds conversion.
    #[error("{field} is too large")]
    TimeoutOverflow {
        /// Timeout field name.
        field: &'static str,
    },
    /// Computing the range proving key failed.
    #[error("failed to compute proving keys")]
    ProvingKeys {
        /// Underlying proving-key setup error.
        #[source]
        source: Box<dyn StdError + Send + Sync>,
    },
    /// Creating the Succinct data fetcher failed.
    #[error("failed to create OPSuccinctDataFetcher")]
    DataFetcher {
        /// Underlying data-fetcher error.
        #[source]
        source: Box<dyn StdError + Send + Sync>,
    },
    /// Creating the SP1 cluster client failed.
    #[error("failed to create SP1 cluster client: {message}")]
    ClusterClient {
        /// Underlying cluster-client error.
        message: String,
    },
    /// Creating the KMS network signer failed.
    #[error("failed to create KMS network signer")]
    KmsNetworkSigner {
        /// Underlying signer error.
        #[source]
        source: Box<dyn StdError + Send + Sync>,
    },
    /// Creating the local network signer failed.
    #[error("failed to create local network signer")]
    LocalNetworkSigner {
        /// Underlying signer error.
        #[source]
        source: Box<dyn StdError + Send + Sync>,
    },
}

#[derive(Debug)]
struct RequiredRpcConfig {
    rpc_config: RPCConfig,
    base_consensus_url: String,
    l1_node_url: String,
}

impl SuccinctBackendBuilder {
    /// Build the selected backend unless cancellation is requested first.
    pub async fn build(
        &self,
        cancel: &CancellationToken,
    ) -> SuccinctBackendBuildResult<Option<Arc<dyn ZkProver>>> {
        if cancel.is_cancelled() {
            return Ok(None);
        }

        match self.backend {
            SuccinctBackendKind::Mock => Ok(Some(Arc::new(MockZkProver))),
            SuccinctBackendKind::DryRun => Ok(Some(Arc::new(DryRunZkProver))),
            SuccinctBackendKind::Cluster => self.build_cluster_backend(cancel).await,
            SuccinctBackendKind::Network => self.build_network_backend(cancel).await,
        }
    }

    /// Build the SP1 cluster backend unless cancellation is requested first.
    async fn build_cluster_backend(
        &self,
        cancel: &CancellationToken,
    ) -> SuccinctBackendBuildResult<Option<Arc<dyn ZkProver>>> {
        let RequiredRpcConfig { rpc_config, base_consensus_url, l1_node_url } =
            self.required_rpcs()?;
        let cluster_rpc = self.required_cluster_value(
            self.cluster.cluster_rpc_endpoint.as_deref(),
            "SP1_CLUSTER_API_ENDPOINT",
        )?;

        info!("ZK_BACKEND=cluster: using Succinct SP1 cluster backend");
        let Some(provider) = self.build_witness_provider(rpc_config, cancel).await? else {
            return Ok(None);
        };
        let Some((artifact_store, artifact_store_config)) =
            self.cluster_artifact_store(cancel).await?
        else {
            return Ok(None);
        };
        let Some(service_client) = Self::complete_unless_cancelled(
            cancel,
            Box::pin(async {
                ClusterServiceClient::new(cluster_rpc.to_owned()).await.map_err(|source| {
                    SuccinctBackendBuildError::ClusterClient { message: source.to_string() }
                })
            }),
            "sp1_cluster_client",
        )
        .await?
        else {
            return Ok(None);
        };
        let config = ClusterZkProverConfig {
            base_consensus_url,
            l1_node_url,
            default_sequence_window: self.default_sequence_window,
            cluster: Arc::new(ClusterProofConfig {
                cluster_rpc: cluster_rpc.to_owned(),
                artifact_store,
                artifact_store_config,
                service_client,
            }),
            timeout: self.cluster_timeout()?,
            range_cycle_limit: self.range_cycle_limit,
            range_gas_limit: self.range_gas_limit,
        };

        Ok(Some(Arc::new(ClusterZkProver::new(provider, config))))
    }

    /// Build the SP1 Network backend unless cancellation is requested first.
    async fn build_network_backend(
        &self,
        cancel: &CancellationToken,
    ) -> SuccinctBackendBuildResult<Option<Arc<dyn ZkProver>>> {
        let RequiredRpcConfig { rpc_config, base_consensus_url, l1_node_url } =
            self.required_rpcs()?;

        info!("ZK_BACKEND=network: using Succinct SP1 Network backend");
        info!("computing range proving key");
        let Some((range_pk, _range_vk, _agg_pk, _agg_vk)) = Self::complete_unless_cancelled(
            cancel,
            Box::pin(async {
                base_proof_succinct_proof_utils::cluster_setup_keys().await.map_err(|source| {
                    SuccinctBackendBuildError::ProvingKeys { source: source.into_boxed_dyn_error() }
                })
            }),
            "proving_keys",
        )
        .await?
        else {
            return Ok(None);
        };
        info!("range proving key computed successfully");

        let Some(provider) = self.build_witness_provider(rpc_config, cancel).await? else {
            return Ok(None);
        };
        let fulfillment_strategy = FulfillmentStrategy::from(self.network.fulfillment_strategy);
        let network_mode = match self.network.fulfillment_strategy {
            SuccinctNetworkFulfillmentStrategy::Auction => NetworkMode::Mainnet,
            SuccinctNetworkFulfillmentStrategy::Hosted
            | SuccinctNetworkFulfillmentStrategy::Reserved => NetworkMode::Reserved,
        };
        let Some(network_signer) = self.network_signer(cancel).await? else {
            return Ok(None);
        };

        info!(
            network_mode = ?network_mode,
            fulfillment_strategy = ?fulfillment_strategy,
            "creating SP1 Network prover"
        );
        let Some(network_prover) = Self::complete_unless_cancelled(
            cancel,
            Box::pin(async {
                Ok(sp1_sdk::ProverClient::builder()
                    .network_for(network_mode)
                    .signer(network_signer)
                    .build()
                    .await)
            }),
            "sp1_network_prover",
        )
        .await?
        else {
            return Ok(None);
        };
        let config = NetworkZkProverConfig {
            base_consensus_url,
            l1_node_url,
            default_sequence_window: self.default_sequence_window,
            network_prover: Arc::new(network_prover),
            range_pk: range_pk.into(),
            fulfillment_strategy,
            timeout: self.network_timeout()?,
            range_cycle_limit: self.range_cycle_limit,
            range_gas_limit: self.range_gas_limit,
        };

        Ok(Some(Arc::new(NetworkZkProver::new(provider, config))))
    }

    /// Build the witness provider unless cancellation is requested first.
    async fn build_witness_provider(
        &self,
        rpcs: RPCConfig,
        cancel: &CancellationToken,
    ) -> SuccinctBackendBuildResult<Option<OpSuccinctWitnessProvider>> {
        let Some(fetcher) = Self::complete_unless_cancelled(
            cancel,
            Box::pin(async {
                OPSuccinctDataFetcher::from_rpc_config_with_rollup_config(rpcs).await.map_err(
                    |source| SuccinctBackendBuildError::DataFetcher {
                        source: source.into_boxed_dyn_error(),
                    },
                )
            }),
            "op_succinct_data_fetcher",
        )
        .await?
        else {
            return Ok(None);
        };
        let fetcher = Arc::new(fetcher);

        Ok(Some(OpSuccinctWitnessProvider::new(fetcher)))
    }

    /// Build the cluster artifact store unless cancellation is requested first.
    async fn cluster_artifact_store(
        &self,
        cancel: &CancellationToken,
    ) -> SuccinctBackendBuildResult<
        Option<(ClusterArtifactStore, sp1_cluster_utils::ArtifactStoreConfig)>,
    > {
        let bucket = self
            .required_cluster_value(self.cluster.s3_bucket.as_deref(), "CLI_S3_BUCKET")?
            .trim()
            .to_owned();
        let region = self
            .required_cluster_value(self.cluster.s3_region.as_deref(), "CLI_S3_REGION")?
            .trim()
            .to_owned();

        info!("using S3 artifact storage");
        let Some(download_client) = Self::complete_unless_cancelled(
            cancel,
            Box::pin(async {
                Ok(sp1_cluster_artifact::s3::S3ArtifactClient::create_s3_sdk_download_client(
                    region.clone(),
                )
                .await)
            }),
            "s3_download_client",
        )
        .await?
        else {
            return Ok(None);
        };
        let download_mode = sp1_cluster_artifact::s3::S3DownloadMode::AwsSDK(download_client);
        let Some(client) = Self::complete_unless_cancelled(
            cancel,
            Box::pin(async {
                Ok(sp1_cluster_artifact::s3::S3ArtifactClient::new(
                    region.clone(),
                    bucket.clone(),
                    32,
                    download_mode,
                )
                .await)
            }),
            "s3_artifact_client",
        )
        .await?
        else {
            return Ok(None);
        };

        Ok(Some((
            ClusterArtifactStore::S3(client),
            sp1_cluster_utils::ArtifactStoreConfig::S3 { bucket, region },
        )))
    }

    /// Build the SP1 Network signer unless cancellation is requested first.
    async fn network_signer(
        &self,
        cancel: &CancellationToken,
    ) -> SuccinctBackendBuildResult<Option<NetworkSigner>> {
        let requester = self.network.requester.as_ref().ok_or_else(|| {
            SuccinctBackendBuildError::MissingConfig {
                backend: SuccinctBackendKind::Network,
                field: "NETWORK_PRIVATE_KEY",
            }
        })?;

        match requester {
            SuccinctNetworkRequester::AwsKmsKeyId(key) => {
                Self::complete_unless_cancelled(
                    cancel,
                    Box::pin(async {
                        NetworkSigner::aws_kms(key).await.map_err(|source| {
                            SuccinctBackendBuildError::KmsNetworkSigner { source: Box::new(source) }
                        })
                    }),
                    "kms_network_signer",
                )
                .await
            }
            SuccinctNetworkRequester::LocalPrivateKey(key) => {
                if cancel.is_cancelled() {
                    return Ok(None);
                }
                NetworkSigner::local(key).map(Some).map_err(|source| {
                    SuccinctBackendBuildError::LocalNetworkSigner { source: Box::new(source) }
                })
            }
        }
    }

    /// Run an initialization operation unless cancellation is requested first.
    ///
    /// Dropping the operation future must be cancellation-safe. Callers should
    /// only wrap initialization futures that tolerate being dropped during
    /// shutdown without corrupting shared state or leaking externally-owned
    /// resources.
    async fn complete_unless_cancelled<T>(
        cancel: &CancellationToken,
        operation: Pin<Box<dyn Future<Output = SuccinctBackendBuildResult<T>> + Send + '_>>,
        operation_name: &'static str,
    ) -> SuccinctBackendBuildResult<Option<T>> {
        tokio::select! {
            result = operation => result.map(Some),
            () = cancel.cancelled() => {
                info!(
                    operation = %operation_name,
                    "cancelled zk prover host worker initialization operation"
                );
                Ok(None)
            }
        }
    }

    /// Return required RPC config for backends that need rollup RPC access.
    fn required_rpcs(&self) -> SuccinctBackendBuildResult<RequiredRpcConfig> {
        let l1_rpc = self.required_url(self.l1_rpc.as_ref(), "L1_NODE_ADDRESS")?;
        let l1_beacon_rpc = self.required_url(self.l1_beacon_rpc.as_ref(), "L1_BEACON_ADDRESS")?;
        let l2_rpc = self.required_url(self.l2_rpc.as_ref(), "L2_NODE_ADDRESS")?;
        let base_consensus_rpc =
            self.required_url(self.base_consensus_rpc.as_ref(), "BASE_CONSENSUS_ADDRESS")?;

        Ok(RequiredRpcConfig {
            rpc_config: RPCConfig {
                l1_rpc: l1_rpc.clone(),
                l1_beacon_rpc: Some(l1_beacon_rpc.clone()),
                l2_rpc: l2_rpc.clone(),
                l2_node_rpc: base_consensus_rpc.clone(),
            },
            base_consensus_url: base_consensus_rpc.as_str().to_owned(),
            l1_node_url: l1_rpc.as_str().to_owned(),
        })
    }

    /// Return a required URL config value.
    fn required_url<'a>(
        &self,
        value: Option<&'a Url>,
        field: &'static str,
    ) -> SuccinctBackendBuildResult<&'a Url> {
        value.ok_or_else(|| SuccinctBackendBuildError::MissingConfig {
            backend: self.backend,
            field,
        })
    }

    /// Return a required cluster config value.
    fn required_cluster_value<'a>(
        &self,
        value: Option<&'a str>,
        field: &'static str,
    ) -> SuccinctBackendBuildResult<&'a str> {
        value.map(str::trim).filter(|value| !value.is_empty()).ok_or_else(|| {
            SuccinctBackendBuildError::MissingConfig {
                backend: SuccinctBackendKind::Cluster,
                field,
            }
        })
    }

    /// Return the cluster timeout.
    fn cluster_timeout(&self) -> SuccinctBackendBuildResult<Duration> {
        Self::timeout(self.cluster.timeout_hours, "SP1_CLUSTER_TIMEOUT_HOURS")
    }

    /// Return the network timeout.
    fn network_timeout(&self) -> SuccinctBackendBuildResult<Duration> {
        Self::timeout(self.network.timeout_hours, "SP1_NETWORK_TIMEOUT_HOURS")
    }

    /// Convert a timeout in hours into a duration.
    fn timeout(timeout_hours: u64, field: &'static str) -> SuccinctBackendBuildResult<Duration> {
        timeout_hours
            .checked_mul(3600)
            .map(Duration::from_secs)
            .ok_or(SuccinctBackendBuildError::TimeoutOverflow { field })
    }
}
