//! Cooperative work observation for long-running CBOR operations.

use core::fmt;

/// Maximum completed work reported by one periodic checkpoint.
///
/// One work unit is either one engine-owned structural/projection step or one byte processed by an
/// engine-owned bulk loop. Enabled operations issue an initial checkpoint with `0`, report completed
/// work in deltas no larger than this interval, and flush a final non-zero remainder before success.
pub const WORK_CHECKPOINT_INTERVAL: usize = 4096;

/// A cooperative observer requested cancellation at a checkpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct WorkCancelled;

impl fmt::Display for WorkCancelled {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CBOR work cancelled")
    }
}

#[cfg(feature = "std")]
impl std::error::Error for WorkCancelled {}

/// Receives deterministic checkpoints from an observed CBOR operation.
///
/// `completed_units` is a delta, not a cumulative total. An enabled operation calls
/// [`checkpoint`](Self::checkpoint) with `0` before its first externally visible side effect. Later
/// calls report only completed engine-owned work, in deltas no larger than
/// [`WORK_CHECKPOINT_INTERVAL`]. A successful operation flushes its final non-zero remainder; it
/// does not emit a redundant terminal zero.
///
/// Returning [`WorkCancelled`] cooperatively stops the operation. The engine maps that decision to
/// [`crate::ErrorCode::WorkCancelled`] at its current confirmed byte position. Cancellation is
/// terminal for an encoder or decoder and does not roll back sink writes, observer side effects, or
/// caller-context side effects that already completed.
///
/// Observation is cooperative: code executing inside a caller callback, a sink's `write` method, or
/// a source-driven projection between calls back into the engine cannot be preempted by this trait.
pub trait WorkObserver {
    /// Whether this observer can receive checkpoints.
    ///
    /// The default is enabled. The engine uses this associated constant to compile all metering and
    /// bulk chunking out of the [`NoopWorkObserver`] path.
    const ENABLED: bool = true;

    /// Internal protocol flag for an observer that already owns a fixed-cadence meter.
    ///
    /// External implementations must leave this at its default. It lets a nested engine forward
    /// work directly into a caller-owned [`WorkSession`] or parent meter instead of introducing a
    /// second cadence and delaying cancellation by another interval.
    #[doc(hidden)]
    const __OWNS_WORK_CADENCE: bool = false;

    /// Return the largest next work chunk that preserves an existing shared cadence.
    ///
    /// This is reserved for the crate's meter/session adapters. External implementations must
    /// leave the default unchanged.
    #[doc(hidden)]
    fn __next_work_chunk(&self, available: usize) -> usize {
        available
    }

    /// Observe a completed-work delta, or request cancellation.
    ///
    /// # Errors
    ///
    /// Returns [`WorkCancelled`] to terminate the active operation.
    fn checkpoint(&mut self, completed_units: usize) -> Result<(), WorkCancelled>;
}

impl<O: WorkObserver + ?Sized> WorkObserver for &mut O {
    const ENABLED: bool = O::ENABLED;
    const __OWNS_WORK_CADENCE: bool = O::__OWNS_WORK_CADENCE;

    #[inline]
    fn __next_work_chunk(&self, available: usize) -> usize {
        O::__next_work_chunk(self, available)
    }

    #[inline]
    fn checkpoint(&mut self, completed_units: usize) -> Result<(), WorkCancelled> {
        O::checkpoint(self, completed_units)
    }
}

/// Zero-sized observer used by ordinary unobserved operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct NoopWorkObserver;

impl WorkObserver for NoopWorkObserver {
    const ENABLED: bool = false;

    #[inline]
    fn checkpoint(&mut self, _completed_units: usize) -> Result<(), WorkCancelled> {
        Ok(())
    }
}

/// Caller-owned fixed-cadence state shared by cooperatively observed operations.
///
/// A session preserves one cadence across multiple lazy iterators or generated view drivers. Create
/// it before the first operation side effect, pass it to each observed operation, and call
/// [`finish`](Self::finish) once the complete caller-owned transaction succeeds. The session does
/// not store byte positions; the engine that detects cancellation maps [`WorkCancelled`] to its
/// current position.
pub struct WorkSession<O: WorkObserver> {
    meter: WorkMeter<O>,
}

impl<O: WorkObserver> WorkSession<O> {
    /// Start a session and emit its initial zero checkpoint.
    ///
    /// # Errors
    ///
    /// Returns [`WorkCancelled`] if the observer rejects the initial checkpoint.
    pub fn new(observer: O) -> Result<Self, WorkCancelled> {
        let mut session = Self {
            meter: WorkMeter::new(observer),
        };
        session.meter.start()?;
        Ok(session)
    }

    /// Report completed engine-owned work through the shared fixed cadence.
    ///
    /// # Errors
    ///
    /// Returns [`WorkCancelled`] if the observer rejects a periodic checkpoint, or if this session
    /// was already cancelled.
    pub fn complete(&mut self, completed_units: usize) -> Result<(), WorkCancelled> {
        self.meter.complete(completed_units)
    }

    /// Borrow this session as the observer for one eager observed operation.
    ///
    /// The returned adapter preserves this session's cadence without transferring ownership of
    /// the session into the operation. After the operation succeeds, the caller can continue using
    /// the session and must eventually call [`finish`](Self::finish) to flush its final remainder.
    #[inline]
    pub fn observer(&mut self) -> impl WorkObserver + '_ {
        WorkSessionObserver { session: self }
    }

    /// Flush the final non-zero completed-work remainder and consume this session.
    ///
    /// A successful call that has no remainder emits no callback. Consuming the session makes
    /// completion a single terminal action and prevents work from being reported after it.
    ///
    /// # Errors
    ///
    /// Returns [`WorkCancelled`] if the observer rejects the final checkpoint, or if this session
    /// was already cancelled.
    pub fn finish(mut self) -> Result<(), WorkCancelled> {
        self.meter.finish()
    }
}

struct WorkSessionObserver<'a, O: WorkObserver> {
    session: &'a mut WorkSession<O>,
}

impl<O: WorkObserver> WorkObserver for WorkSessionObserver<'_, O> {
    const ENABLED: bool = O::ENABLED;
    const __OWNS_WORK_CADENCE: bool = true;

    #[inline]
    fn __next_work_chunk(&self, available: usize) -> usize {
        self.session.meter.next_chunk(available)
    }

    #[inline]
    fn checkpoint(&mut self, completed_units: usize) -> Result<(), WorkCancelled> {
        self.session.complete(completed_units)
    }
}

/// Operation-local fixed-cadence meter.
pub struct WorkMeter<O: WorkObserver> {
    observer: O,
    pending: usize,
    started: bool,
    stopped: bool,
}

impl<O: WorkObserver> WorkMeter<O> {
    #[inline]
    pub(crate) const fn new(observer: O) -> Self {
        Self {
            observer,
            pending: 0,
            started: false,
            stopped: false,
        }
    }

    #[inline]
    pub(crate) fn start(&mut self) -> Result<(), WorkCancelled> {
        if !O::ENABLED {
            return Ok(());
        }
        if self.stopped {
            return Err(WorkCancelled);
        }
        if !self.started {
            if let Err(cancelled) = self.observer.checkpoint(0) {
                self.stopped = true;
                return Err(cancelled);
            }
            self.started = true;
        }
        Ok(())
    }

    #[inline]
    pub(crate) fn next_chunk(&self, available: usize) -> usize {
        if O::ENABLED {
            if O::__OWNS_WORK_CADENCE {
                if available == 0 {
                    0
                } else {
                    let maximum = available.min(WORK_CHECKPOINT_INTERVAL);
                    self.observer.__next_work_chunk(available).clamp(1, maximum)
                }
            } else {
                let remaining = WORK_CHECKPOINT_INTERVAL - self.pending;
                if available < remaining {
                    available
                } else {
                    remaining
                }
            }
        } else {
            available
        }
    }

    #[inline]
    pub(crate) fn complete(&mut self, mut completed_units: usize) -> Result<(), WorkCancelled> {
        if !O::ENABLED {
            return Ok(());
        }
        self.start()?;
        if completed_units == 0 {
            return Ok(());
        }
        if O::__OWNS_WORK_CADENCE {
            while completed_units != 0 {
                let delta = self.next_chunk(completed_units);
                completed_units -= delta;
                if let Err(cancelled) = self.observer.checkpoint(delta) {
                    self.stopped = true;
                    return Err(cancelled);
                }
            }
            return Ok(());
        }
        while completed_units != 0 {
            let delta = self.next_chunk(completed_units);
            self.pending += delta;
            completed_units -= delta;
            if self.pending == WORK_CHECKPOINT_INTERVAL {
                self.pending = 0;
                if let Err(cancelled) = self.observer.checkpoint(WORK_CHECKPOINT_INTERVAL) {
                    self.stopped = true;
                    return Err(cancelled);
                }
            }
        }
        Ok(())
    }

    #[inline]
    pub(crate) fn finish(&mut self) -> Result<(), WorkCancelled> {
        if !O::ENABLED {
            return Ok(());
        }
        self.start()?;
        if self.pending != 0 {
            let completed = core::mem::take(&mut self.pending);
            if let Err(cancelled) = self.observer.checkpoint(completed) {
                self.stopped = true;
                return Err(cancelled);
            }
        }
        Ok(())
    }
}

// A nested engine can borrow its parent's meter as its observer. The nested initial zero is ignored,
// while completed deltas feed the parent's cadence without resetting it.
impl<O: WorkObserver> WorkObserver for WorkMeter<O> {
    const ENABLED: bool = O::ENABLED;
    const __OWNS_WORK_CADENCE: bool = true;

    #[inline]
    fn __next_work_chunk(&self, available: usize) -> usize {
        self.next_chunk(available)
    }

    #[inline]
    fn checkpoint(&mut self, completed_units: usize) -> Result<(), WorkCancelled> {
        self.complete(completed_units)
    }
}
