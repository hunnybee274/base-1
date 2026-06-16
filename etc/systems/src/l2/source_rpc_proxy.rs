//! L2 source RPC proxies for system test consensus scenarios.

use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    time::Duration,
};

use base_builder_core::test_utils::get_available_port;
use eyre::{Result, WrapErr};
use jsonrpsee::{
    RpcModule,
    server::{Server, ServerHandle},
    types::ErrorObjectOwned,
    types::error::ErrorCode,
};
use serde_json::{Value, json};
use tracing::info;
use url::Url;

/// Configuration for a source RPC proxy that strips `requestsHash` from block responses.
#[derive(Debug, Clone)]
pub struct RequestsHashStrippingSourceRpcProxyConfig {
    /// Upstream source L2 RPC endpoint.
    pub source_l2_rpc_url: Url,
    /// Optional fixed proxy RPC port.
    pub rpc_port: Option<u16>,
}

/// Running source RPC proxy that strips `requestsHash` from `eth_getBlockByNumber` responses.
pub struct RequestsHashStrippingSourceRpcProxy {
    rpc_addr: SocketAddr,
    handle: ServerHandle,
}

impl std::fmt::Debug for RequestsHashStrippingSourceRpcProxy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RequestsHashStrippingSourceRpcProxy")
            .field("rpc_addr", &self.rpc_addr)
            .finish()
    }
}

impl RequestsHashStrippingSourceRpcProxy {
    /// Starts the proxy with the given configuration.
    pub async fn start(config: RequestsHashStrippingSourceRpcProxyConfig) -> Result<Self> {
        let rpc_port = config.rpc_port.unwrap_or_else(get_available_port);
        let rpc_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), rpc_port);
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(60))
            .build()
            .wrap_err("failed to build source RPC proxy client")?;

        let mut module = RpcModule::new(());

        let block_number_client = client.clone();
        let block_number_upstream = config.source_l2_rpc_url.clone();
        module
            .register_async_method("eth_blockNumber", move |_, _, _| {
                let client = block_number_client.clone();
                let upstream = block_number_upstream.clone();
                async move {
                    Self::forward_rpc(&client, &upstream, "eth_blockNumber", json!([])).await
                }
            })
            .wrap_err("failed to register eth_blockNumber proxy method")?;

        let block_by_number_client = client;
        let block_by_number_upstream = config.source_l2_rpc_url;
        module
            .register_async_method("eth_getBlockByNumber", move |params, _, _| {
                let client = block_by_number_client.clone();
                let upstream = block_by_number_upstream.clone();
                async move {
                    let params = params
                        .parse::<Vec<Value>>()
                        .map_err(|e| Self::invalid_params_error(format!("invalid params: {e}")))?;
                    let mut result = Self::forward_rpc(
                        &client,
                        &upstream,
                        "eth_getBlockByNumber",
                        json!(params),
                    )
                    .await?;
                    Self::strip_requests_hash(&mut result);
                    Ok::<_, ErrorObjectOwned>(result)
                }
            })
            .wrap_err("failed to register eth_getBlockByNumber proxy method")?;

        let server =
            Server::builder().build(rpc_addr).await.wrap_err("failed to bind source RPC proxy")?;
        let rpc_addr = server.local_addr().wrap_err("failed to read source RPC proxy addr")?;
        let handle = server.start(module);

        info!(rpc_port = rpc_addr.port(), "source RPC proxy started");
        Ok(Self { rpc_addr, handle })
    }

    /// Returns the RPC URL for this proxy.
    pub fn rpc_url(&self) -> Url {
        Url::parse(&format!("http://{}:{}", self.rpc_addr.ip(), self.rpc_addr.port()))
            .expect("valid RPC URL")
    }

    /// Returns the RPC port.
    pub const fn rpc_port(&self) -> u16 {
        self.rpc_addr.port()
    }

    async fn forward_rpc(
        client: &reqwest::Client,
        upstream: &Url,
        method: &str,
        params: Value,
    ) -> Result<Value, ErrorObjectOwned> {
        let request = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params,
        });
        let response = client
            .post(upstream.clone())
            .json(&request)
            .send()
            .await
            .map_err(|e| Self::internal_error(format!("upstream request failed: {e}")))?
            .json::<Value>()
            .await
            .map_err(|e| Self::internal_error(format!("upstream response decode failed: {e}")))?;

        if let Some(error) = response.get("error") {
            return Err(Self::internal_error(format!("upstream RPC error for {method}: {error}")));
        }

        response.get("result").cloned().ok_or_else(|| {
            Self::internal_error(format!("upstream response for {method} omitted result"))
        })
    }

    fn strip_requests_hash(value: &mut Value) {
        if let Some(block) = value.as_object_mut() {
            block.remove("requestsHash");
        }
    }

    fn internal_error(message: String) -> ErrorObjectOwned {
        ErrorObjectOwned::owned(ErrorCode::InternalError.code(), message, None::<()>)
    }

    fn invalid_params_error(message: String) -> ErrorObjectOwned {
        ErrorObjectOwned::owned(ErrorCode::InvalidParams.code(), message, None::<()>)
    }
}

impl Drop for RequestsHashStrippingSourceRpcProxy {
    fn drop(&mut self) {
        let _ = self.handle.stop();
    }
}
