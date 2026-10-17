//! src/rpc/mod.rs — the axum HTTP server and the JSON-RPC 2.0 router.
//!
//! The server parses a single JSON-RPC request per HTTP POST, routes the
//! method name to its handler in `handlers`, and answers with the
//! standard success or error envelope. Rate limiting runs per client IP
//! with token buckets sized for an honest wallet or explorer: refill
//! bounds the long-run request rate and the burst cap absorbs scripted
//! polling. The bucket map is swept periodically so a distributed flood
//! cannot grow it without bound: entries idle past the sweep horizon are
//! dropped, and the sweep itself runs only when the map exceeds a
//! watermark, so steady-state serving pays nothing for it. Every mutex
//! is poison-safe: a panicking request task degrades its own request to
//! an internal error instead of poisoning the lock for the process
//! lifetime. The two control methods, `stop` and `mine`, reach the node
//! through the command channel installed at startup; an endpoint without
//! a configured channel answers them with a plain internal error.
//!
//! Layout:
//! - `handlers` — the individual JSON-RPC method handlers

mod handlers;

use axum::extract::{ConnectInfo, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::post;
use axum::{Json, Router};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// The maximum number of per-IP rate-limit buckets retained before the
/// sweep pass runs. Distributed sources can create many entries; the
/// watermark bounds the map between sweeps and bounds the sweep's own
/// cost.
const BUCKET_SWEEP_WATERMARK: usize = 4096;

/// A per-IP entry is dropped once it has been idle at least this long.
const BUCKET_IDLE_HORIZON: Duration = Duration::from_secs(600);

/// The per-IP burst capacity in tokens: a new bucket starts full, and
/// refill adds two tokens per second up to this cap.
const BUCKET_CAPACITY: f64 = 5.0;

/// The linear refill rate in tokens per second.
const BUCKET_REFILL_PER_SEC: f64 = 2.0;

/// Shared RPC state: the per-IP rate-limit buckets and the node command
/// channel. Handlers receive it as axum state, so no global mutable
/// state backs the HTTP surface.
pub(super) struct RpcShared {
    /// Per-IP token buckets. The map grows by one small entry per new
    /// source address and is swept at the watermark, so its size is
    /// bounded by `BUCKET_SWEEP_WATERMARK` plus the peak number of
    /// distinct active sources between sweeps.
    pub(super) buckets: Mutex<HashMap<String, (f64, Instant)>>,
    /// The node command channel: the sender installed at startup lets
    /// the control methods reach the event loop; None when this endpoint
    /// was started without node control (for example an external
    /// fronting server that owns the node).
    pub(super) cmd: Option<tokio::sync::mpsc::Sender<crate::p2p::NodeCommand>>,
}

impl RpcShared {
    fn new(cmd: Option<tokio::sync::mpsc::Sender<crate::p2p::NodeCommand>>) -> Self {
        Self {
            buckets: Mutex::new(HashMap::new()),
            cmd,
        }
    }

    /// Admits one request from `ip`, refilling the bucket linearly since
    /// the caller's last request. The map sweep runs only past the
    /// watermark, so a quiet node never pays for it. The lock is
    /// poison-safe: a panicked holder cannot take the rate limiter down
    /// for every later request.
    fn rate_limit(&self, ip: &str) -> bool {
        let mut buckets = self.buckets.lock().unwrap_or_else(|e| e.into_inner());
        if buckets.len() > BUCKET_SWEEP_WATERMARK {
            let now = Instant::now();
            buckets.retain(|_, (_, last)| now.duration_since(*last) <= BUCKET_IDLE_HORIZON);
        }
        let entry = buckets
            .entry(ip.to_string())
            .or_insert((BUCKET_CAPACITY, Instant::now()));
        let (ref mut tokens, ref mut last) = *entry;
        let now = Instant::now();
        let elapsed = now.duration_since(*last).as_secs_f64();
        *last = now;
        *tokens = (*tokens + elapsed * BUCKET_REFILL_PER_SEC).min(BUCKET_CAPACITY);
        if *tokens >= 1.0 {
            *tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// A JSON-RPC error: numeric code, message, and optional structured
/// data. Codes follow the JSON-RPC 2.0 convention: -32700 parse, -32600
/// invalid request, -32601 method not found, -32602 invalid params,
/// -32603 internal error.
#[derive(Debug)]
pub(super) struct RpcError {
    pub(super) code: i64,
    pub(super) message: String,
    pub(super) data: Option<Value>,
}

impl RpcError {
    fn invalid_params(message: &str) -> Self {
        Self {
            code: -32602,
            message: format!("invalid params: {message}"),
            data: None,
        }
    }

    fn invalid_tx(message: &str) -> Self {
        Self {
            code: -32003,
            message: format!("invalid transaction: {message}"),
            data: None,
        }
    }

    fn internal(message: &str) -> Self {
        Self {
            code: -32603,
            message: message.to_string(),
            data: None,
        }
    }
}

/// Start the JSON-RPC HTTP server on `port` without node control: the
/// control methods answer with an internal error on this endpoint.
pub async fn serve(port: u16) -> std::io::Result<()> {
    serve_with(port, None).await
}

/// Start the JSON-RPC HTTP server on `port` with a node command channel
/// installed. The control methods forward `stop` and `mine` commands to
/// the event loop through the sender.
pub async fn serve_with(
    port: u16,
    cmd: Option<tokio::sync::mpsc::Sender<crate::p2p::NodeCommand>>,
) -> std::io::Result<()> {
    let shared = Arc::new(RpcShared::new(cmd));
    let app = Router::new().route("/", post(handle)).with_state(shared);
    let listener = tokio::net::TcpListener::bind(("0.0.0.0", port)).await?;
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
}

/// The axum handler: one JSON-RPC request per POST, routed by method
/// name to the handlers. Malformed JSON is the node's problem to report
/// as a parse error, not the transport's, so unparsable bodies get the
/// -32700 envelope with a 200 status instead of an HTTP error.
async fn handle(
    State(shared): State<Arc<RpcShared>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    body: String,
) -> impl IntoResponse {
    if !shared.rate_limit(&addr.ip().to_string()) {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(json!({ "error": "rate limited" })),
        );
    }
    let Ok(request) = serde_json::from_str::<Value>(&body) else {
        return (
            StatusCode::OK,
            Json(
                json!({"jsonrpc": "2.0", "error": {"code": -32700, "message": "parse error"}, "id": null}),
            ),
        );
    };
    let id = request.get("id").cloned().unwrap_or(Value::Null);
    let method = request
        .get("method")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let params = request.get("params").cloned().unwrap_or(Value::Null);
    match dispatch(&shared, method, &params).await {
        Ok(result) => (
            StatusCode::OK,
            Json(json!({"jsonrpc": "2.0", "result": result, "id": id})),
        ),
        Err(err) => {
            let mut error = json!({"code": err.code, "message": err.message});
            if let Some(data) = err.data {
                error["data"] = data;
            }
            (
                StatusCode::OK,
                Json(json!({"jsonrpc": "2.0", "error": error, "id": id})),
            )
        }
    }
}

/// Route a JSON-RPC method name to its handler. Every data method lives
/// in `handlers`; the two control methods forward to the node command
/// channel installed in the shared state.
pub(super) async fn dispatch(
    shared: &RpcShared,
    method: &str,
    params: &Value,
) -> Result<Value, RpcError> {
    match method {
        "getBalance" => handlers::handle_get_balance(params).await,
        "getBlock" => handlers::handle_get_block(params).await,
        "sendRawTx" => handlers::handle_send_raw_tx(params).await,
        "getTip" => handlers::handle_get_tip().await,
        "getDifficulty" => handlers::handle_get_difficulty().await,
        "getPageProof" => handlers::handle_get_page_proof(params).await,
        "getStatus" => handlers::handle_get_status().await,
        "getMempool" => handlers::handle_get_mempool(params).await,
        "getTreasuryState" => handlers::handle_get_treasury_state(params).await,
        "buildTreasuryBuy" => handlers::handle_build_treasury_buy(params).await,
        "buildTreasurySell" => handlers::handle_build_treasury_sell(params).await,
        "stop" => handlers::handle_stop(shared).await,
        "mine" => handlers::handle_mine(shared).await,
        _ => Err(RpcError {
            code: -32601,
            message: format!("method not found: {method}"),
            data: None,
        }),
    }
}

#[cfg(test)]
mod rpc_tests {
    use super::*;

    /// A request envelope parses into the id, method, and params the
    /// router reads; unparsable bodies carry the parse-error code.
    #[test]
    fn envelope_parse_and_method_extraction() {
        let request: Value =
            serde_json::from_str(r#"{"jsonrpc":"2.0","method":"getTip","params":[],"id":1}"#)
                .expect("a well-formed envelope parses");
        assert_eq!(request.get("id").cloned().unwrap_or(Value::Null), json!(1));
        assert_eq!(
            request
                .get("method")
                .and_then(Value::as_str)
                .unwrap_or_default(),
            "getTip"
        );
        let bad: Result<Value, _> = serde_json::from_str("{not json");
        assert!(
            bad.is_err(),
            "an unparsable body is rejected before routing"
        );
    }

    #[tokio::test]
    async fn dispatch_routes_results_and_unknown_methods() {
        let shared = RpcShared::new(None);
        let params = serde_json::from_str("[]").unwrap();
        let result = dispatch(&shared, "getTip", &params).await;
        assert!(result.is_ok(), "getTip resolves through the chain cache");
        let unknown = dispatch(&shared, "nope", &params).await;
        match unknown {
            Err(err) => assert_eq!(err.code, -32601),
            Ok(_) => panic!("an unknown method must not resolve"),
        }
    }

    #[tokio::test]
    async fn control_methods_report_unconfigured_channel() {
        // Without an installed command channel the control methods answer
        // with a plain internal error, never with a false success.
        let shared = RpcShared::new(None);
        let params = serde_json::from_str("[]").unwrap();
        match dispatch(&shared, "stop", &params).await {
            Err(err) => assert_eq!(err.code, -32603),
            Ok(_) => panic!("stop without a channel must fail closed"),
        }
    }

    #[test]
    fn rate_limit_allows_up_to_the_burst_cap_then_refuses() {
        // A fresh bucket holds exactly BUCKET_CAPACITY tokens: that many
        // back-to-back requests are admitted, the next one is refused.
        // The calls run within one refill quantum, so the linear refill
        // does not smuggle an extra token in.
        let shared = RpcShared::new(None);
        let ip = "10.0.0.1";
        for _ in 0..BUCKET_CAPACITY as usize {
            assert!(shared.rate_limit(ip));
        }
        assert!(!shared.rate_limit(ip));
    }

    #[test]
    fn sweep_reclaims_idle_entries_past_the_watermark() {
        // Fill the map with strictly more distinct entries than the
        // watermark, every one idle beyond the horizon: the next
        // admission crosses the watermark, the sweep reclaims all idle
        // entries, and the map ends holding exactly the one active entry
        // created by that admission.
        let shared = RpcShared::new(None);
        {
            let mut buckets = shared.buckets.lock().unwrap();
            for i in 0..=BUCKET_SWEEP_WATERMARK {
                buckets.insert(
                    format!("10.1.0.{i}"),
                    (
                        BUCKET_CAPACITY,
                        Instant::now() - BUCKET_IDLE_HORIZON - Duration::from_secs(1),
                    ),
                );
            }
        }
        assert!(shared.rate_limit("10.0.0.1"));
        assert_eq!(
            shared.buckets.lock().unwrap().len(),
            1,
            "the sweep reclaims every idle entry and keeps only the active one"
        );
    }

    #[test]
    fn poisoned_bucket_lock_still_serves() {
        // A panicking holder leaves the lock poisoned; the rate limiter
        // recovers the guard and keeps admitting requests instead of
        // failing every later call for the process lifetime.
        let shared = RpcShared::new(None);
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = shared.buckets.lock().unwrap();
            panic!("simulated panic while holding the bucket lock");
        }));
        assert!(shared.rate_limit("10.0.0.2"));
    }
}
