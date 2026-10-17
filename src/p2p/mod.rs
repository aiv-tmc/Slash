//! P2P networking: the libp2p stack, the mempool, the onion relay, and
//! the sync logic. The public surface re-exports the node, its command
//! channel, the wire protocol types, the content-based transaction id,
//! and the shared limits.

mod behaviour;
mod conn;
mod handlers;
mod housekeeping;
mod lifecycle;
mod limits;
mod maintenance;
mod mempool;
mod mine;
mod node;
mod replay;
#[cfg(test)]
mod tests;
mod util;
mod wire;

pub use limits::*;
pub use mempool::tx_id;
pub use node::{Node, NodeCommand};
pub use wire::{Req, Resp};
