//! The Main-profile reflector: a transparent one-to-many fan-out relay (libRIST
//! `reflector`). It listens for one inbound RIST flow, recovers and orders it through a
//! full receiver (ARQ, reorder, dedup), then re-emits every recovered packet to each
//! output **preserving its original `(seq, source_time)`** via [`Sender::send_block`].
//! Downstream receivers see the same sequence space and source clock as the origin, so
//! the relay is transparent: an unrecoverable gap on the input reproduces as the same
//! gap on every output. Main profile only.

use std::net::SocketAddr;

use crate::config::{Config, Profile};
use crate::driver::MediaBlock;
use crate::error::Error;
use crate::runtime::{Runtime, TokioRuntime};
use crate::sender::{Sender, dial_with};
use crate::stats::StatsCell;
use tokio::sync::mpsc;

/// A running Main-profile reflector. Created with [`reflect`]; it owns the inbound
/// receiver, the outbound senders, and a background pump that forwards each recovered
/// packet to every output transparently. Drop or [`close`](Reflector::close) it to
/// tear everything down.
#[derive(Debug)]
pub struct Reflector {
    cfg: Config,
    local: SocketAddr,
    outputs: usize,
    input_stats: StatsCell,
    input_task: tokio::task::JoinHandle<()>,
    pump_task: tokio::task::JoinHandle<()>,
}

impl Reflector {
    /// The configuration the reflector was created with.
    #[must_use]
    pub fn config(&self) -> &Config {
        &self.cfg
    }

    /// The bound local input address (where the upstream sender connects).
    ///
    /// # Errors
    /// Never; the result is for API symmetry (the address is resolved at construction).
    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        Ok(self.local)
    }

    /// The number of output destinations the input flow is fanned out to.
    #[must_use]
    pub fn output_count(&self) -> usize {
        self.outputs
    }

    /// A snapshot of the **input** flow's receiver counters (recovered, lost, RTT, …).
    /// The reflected outputs are fire-and-forget; their per-output stats are not tracked.
    #[must_use]
    pub fn stats(&self) -> crate::Stats {
        self.input_stats.snapshot()
    }

    /// Shuts the reflector down: stops the pump (closing every output sender) and the
    /// inbound receiver, releasing all sockets.
    ///
    /// # Errors
    /// Never; the result is for API symmetry and forward compatibility.
    pub async fn close(self) -> Result<(), Error> {
        self.pump_task.abort();
        self.input_task.abort();
        Ok(())
    }
}

/// Starts a transparent reflector: listen for one inbound Main-profile flow on `input`
/// and re-emit every recovered packet to each address in `outputs`, preserving the
/// original `(seq, source_time)`. `input` and each `output` may be a bare `IP:port` or
/// a `rist://` URL whose query parameters refine `cfg`. `cfg` must select the Main
/// profile (`Profile::Main`).
///
/// # Errors
/// Returns [`Error::Url`]/[`Error::InvalidAddr`] for a bad address, [`Error::Config`]
/// for an invalid configuration, [`Error::Unimplemented`] if `cfg` is not Main or
/// `outputs` is empty, or [`Error::Io`] if a socket cannot be bound.
pub async fn reflect(input: &str, outputs: &[&str], cfg: Config) -> Result<Reflector, Error> {
    reflect_with(input, outputs, cfg, &TokioRuntime).await
}

/// Like [`reflect`], but binds every socket through `rt`.
///
/// # Errors
/// As [`reflect`].
pub async fn reflect_with(
    input: &str,
    outputs: &[&str],
    cfg: Config,
    rt: &dyn Runtime,
) -> Result<Reflector, Error> {
    if cfg.profile != Profile::Main {
        return Err(Error::Unimplemented("reflector requires the Main profile"));
    }
    if outputs.is_empty() {
        return Err(Error::Unimplemented("reflector needs at least one output"));
    }
    // Resolve the input listen address (a bare IP:port or a rist:// URL refining cfg).
    let (in_addr, cfg) = if input.contains("://") {
        crate::url::parse_url(input, cfg)?
    } else {
        (input.to_string(), cfg)
    };
    cfg.validate()?;
    let local: SocketAddr = in_addr
        .parse()
        .map_err(|_| Error::InvalidAddr(in_addr.clone()))?;

    // Dial each output as an ordinary Main sender (each gets its own send_block channel).
    let mut senders = Vec::with_capacity(outputs.len());
    for &out in outputs {
        senders.push(dial_with(out, cfg.clone(), rt).await?);
    }

    let spawned = crate::session::build_reflector_input(rt, &cfg, local)?;
    let pump_task = tokio::spawn(pump(spawned.block_out, senders));
    tracing::debug!(
        target: crate::logging::SESSION,
        %local,
        outputs = outputs.len(),
        "rist: reflector started"
    );
    // The input close-reason flag is recorded by the driver but the reflector surfaces
    // no recv error to anyone, so it is intentionally not retained.
    let _ = spawned.close;
    Ok(Reflector {
        cfg,
        local: spawned.local,
        outputs: outputs.len(),
        input_stats: spawned.stats,
        input_task: spawned.task,
        pump_task,
    })
}

/// The reflector pump: forward each recovered input block to every output, preserving
/// `(seq, source_time)`. The fan-out is best-effort — a dead or back-pressured output
/// is skipped for that block (its `send_block` errors are ignored) so one stalled
/// destination never blocks the others or the relay.
async fn pump(mut block_out: mpsc::Receiver<MediaBlock>, senders: Vec<Sender>) {
    while let Some(MediaBlock {
        seq,
        source_time,
        payload,
    }) = block_out.recv().await
    {
        for s in &senders {
            let _ = s.send_block(&payload, Some(seq), Some(source_time)).await;
        }
    }
}
