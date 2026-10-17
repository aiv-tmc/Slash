//! Wire format: the negotiated protocol name, the length-prefixed bincode
//! codec, and the request/response frame types.
//!
//! Every request-response message is a 4-byte little-endian length header
//! followed by a bincode payload, capped at `MAX_FRAME` bytes: the declared
//! length is validated against the cap before any allocation, so a
//! malicious peer cannot force giant buffers. A truncated stream, an
//! oversized declared length, or a short read all surface as io errors and
//! terminate the substream.

use futures::io::{AsyncReadExt, AsyncWriteExt};
use libp2p::request_response;
use serde::{Deserialize, Serialize};

use super::limits::MAX_FRAME;

/// The request-response protocol name negotiated during the libp2p
/// handshake. Versioned so incompatible wire revisions refuse to connect.
const REQ_RESP_PROTOCOL: &str = "/slash/req-resp/0.4.2";

/// Protocol identifier negotiated for the request-response stream upgrade.
/// The request-response behaviour names its protocol as a string; the
/// upgrade negotiates this name in both directions on every substream.
#[derive(Clone, Debug)]
pub struct SlashProtocol;

impl AsRef<str> for SlashProtocol {
    fn as_ref(&self) -> &str {
        REQ_RESP_PROTOCOL
    }
}

/// Length-prefixed bincode codec for the request-response sub-protocol.
#[derive(Clone, Debug, Default)]
pub struct BincodeCodec;

/// Read one length-prefixed frame from the substream and return the raw
/// payload. The length header is validated against `MAX_FRAME` before the
/// payload buffer is allocated.
async fn read_frame<T>(io: &mut T) -> std::io::Result<Vec<u8>>
where
    T: futures::io::AsyncRead + Unpin,
{
    let mut len_buf = [0u8; 4];
    io.read_exact(&mut len_buf).await?;
    let len = u32::from_le_bytes(len_buf) as usize;
    if len > MAX_FRAME {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "frame exceeds the maximum size",
        ));
    }
    let mut payload = vec![0u8; len];
    io.read_exact(&mut payload).await?;
    Ok(payload)
}

/// Serialize a value with bincode and write it as one length-prefixed
/// frame.
async fn write_frame<T, S>(io: &mut T, value: &S) -> std::io::Result<()>
where
    T: futures::io::AsyncWrite + Unpin,
    S: serde::Serialize,
{
    let payload = bincode::serialize(value)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    io.write_all(&(payload.len() as u32).to_le_bytes()).await?;
    io.write_all(&payload).await?;
    io.flush().await?;
    Ok(())
}

#[async_trait::async_trait]
impl request_response::Codec for BincodeCodec {
    type Protocol = SlashProtocol;
    type Request = Req;
    type Response = Resp;

    async fn read_request<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
    ) -> std::io::Result<Self::Request>
    where
        T: futures::io::AsyncRead + Unpin + Send,
    {
        let payload = read_frame(io).await?;
        bincode::deserialize(&payload)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    }

    async fn read_response<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
    ) -> std::io::Result<Self::Response>
    where
        T: futures::io::AsyncRead + Unpin + Send,
    {
        let payload = read_frame(io).await?;
        bincode::deserialize(&payload)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    }

    async fn write_request<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
        req: Self::Request,
    ) -> std::io::Result<()>
    where
        T: futures::io::AsyncWrite + Unpin + Send,
    {
        write_frame(io, &req).await
    }

    async fn write_response<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
        res: Self::Response,
    ) -> std::io::Result<()>
    where
        T: futures::io::AsyncWrite + Unpin + Send,
    {
        write_frame(io, &res).await
    }
}

/// Request types for the request-response sub-protocol. All variants are
/// length-prefixed bincode inside a bounded frame.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Req {
    /// Fetch one full block by absolute height.
    GetBlock(u64),
    /// Fetch a half-open range of full blocks [from, to).
    GetBlocks(u64, u64),
    /// Ask for the peer's current tip.
    GetTip,
    /// Fetch a range of light headers [from, to).
    GetHeaders(u64, u64),
    /// Ask for the peer's onion routing key (legacy, unauthenticated).
    GetOnionKey,
    /// Ask for the peer's onion routing key with a nonce challenge: the
    /// peer must return the key together with a signature of the nonce
    /// from its Ed25519 identity, which binds the onion key to the peer.
    GetOnionKeyV2([u8; 32]),
    /// Relay a peeled onion envelope to the next hop.
    ForwardOnion(Vec<u8>),
}

/// Response types paired with `Req`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Resp {
    /// The requested block, or None past the peer's tip.
    Block(Option<crate::chain::Block>),
    /// A batch of blocks (possibly truncated by the frame bound).
    Blocks(Vec<crate::chain::Block>),
    /// Tip height and hash.
    Tip(u64, [u8; 32]),
    /// A batch of light headers.
    Headers(Vec<crate::chain::BlockHeader>),
    /// The onion public key (legacy response, unauthenticated).
    OnionKey([u8; 32]),
    /// The onion public key with the requested nonce and an Ed25519
    /// signature over (nonce || onion_key) from the peer identity.
    OnionKeyV2([u8; 32], [u8; 32], Vec<u8>),
    /// Acknowledgement for fire-and-forget relays.
    Ack,
}
