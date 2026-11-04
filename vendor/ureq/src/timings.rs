use std::fmt;
use std::iter::once;
use std::sync::Arc;

use crate::config::Timeouts;
use crate::transport::time::{Duration, Instant};

/// The various timeouts.
///
/// Each enum corresponds to a value in
/// [`ConfigBuilder::timeout_xxx`][crate::config::ConfigBuilder::timeout_global].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Timeout {
    /// Timeout for an individual transport read.
    PerRead,

    /// Timeout for an individual transport write.
    PerWrite,

    /// Total operation timeout, including redirects and the response body.
    Global,

    /// Total timeout for one HTTP exchange, reset when following a redirect.
    PerCall,

    /// Timeout while resolving the target hostname locally.
    Resolve,

    /// Total connection setup timeout, including proxy DNS, negotiation, and TLS.
    Connect,

    /// Total timeout while sending the request headers.
    SendRequest,

    /// Internal value never seen outside ureq (since awaiting 100 is expected
    /// to timeout).
    #[doc(hidden)]
    Await100,

    /// Total timeout while sending the request body.
    SendBody,

    /// Total timeout while waiting for and receiving the response headers.
    RecvResponse,

    /// Total response body timeout, starting after complete response headers.
    RecvBody,
}

impl Timeout {
    /// Give the immediate preceeding Timeout
    fn preceeding(&self) -> impl Iterator<Item = Timeout> {
        let prev: &[Timeout] = match self {
            Timeout::Resolve => &[Timeout::PerCall],
            Timeout::Connect => &[Timeout::Resolve],
            Timeout::SendRequest => &[Timeout::Connect],
            Timeout::Await100 => &[Timeout::SendRequest],
            Timeout::SendBody => &[Timeout::SendRequest, Timeout::Await100],
            Timeout::RecvResponse => &[Timeout::SendRequest, Timeout::Await100, Timeout::SendBody],
            Timeout::RecvBody => &[Timeout::RecvResponse],
            _ => &[],
        };

        prev.iter().copied()
    }

    /// All timeouts to check
    fn timeouts_to_check(&self) -> impl Iterator<Item = Timeout> {
        // Always check Global and PerCall
        once(*self).chain([Timeout::Global, Timeout::PerCall])
    }

    /// Get the corresponding configured timeout
    fn configured_timeout(&self, timeouts: &Timeouts) -> Option<Duration> {
        match self {
            Timeout::PerRead | Timeout::PerWrite => None,
            Timeout::Global => timeouts.global,
            Timeout::PerCall => timeouts.per_call,
            Timeout::Resolve => timeouts.resolve,
            Timeout::Connect => timeouts.connect,
            Timeout::SendRequest => timeouts.send_request,
            Timeout::Await100 => timeouts.await_100,
            Timeout::SendBody => timeouts.send_body,
            Timeout::RecvResponse => timeouts.recv_response,
            Timeout::RecvBody => timeouts.recv_body,
        }
        .map(Into::into)
    }
}

#[derive(Default, Debug)]
pub(crate) struct CallTimings {
    timeouts: Box<Timeouts>,
    per_read: Option<Duration>,
    per_write: Option<Duration>,
    current_time: CurrentTime,
    times: Vec<(Timeout, Instant)>,
}

impl CallTimings {
    pub(crate) fn new(timeouts: Timeouts, current_time: CurrentTime) -> Self {
        let mut times = Vec::with_capacity(8);

        let now = current_time.now();
        times.push((Timeout::Global, now));
        times.push((Timeout::PerCall, now));

        CallTimings {
            timeouts: Box::new(timeouts),
            per_read: None,
            per_write: None,
            current_time,
            times,
        }
    }

    pub(crate) fn with_io_timeouts(mut self, config: &crate::config::Config) -> Self {
        self.per_read = config.timeout_per_read().map(Into::into);
        self.per_write = config.timeout_per_write().map(Into::into);
        self
    }

    pub(crate) fn new_call(mut self) -> CallTimings {
        self.times.truncate(1); // Global is in position 0.
        self.times.push((Timeout::PerCall, self.current_time.now()));

        CallTimings {
            timeouts: self.timeouts,
            per_read: self.per_read,
            per_write: self.per_write,
            current_time: self.current_time,
            times: self.times,
        }
    }

    pub(crate) fn current_time(&self) -> Arc<dyn Fn() -> Instant + Send + Sync + 'static> {
        self.current_time.0.clone()
    }

    pub(crate) fn now(&self) -> Instant {
        self.current_time.now()
    }

    pub(crate) fn record_time(&mut self, timeout: Timeout) {
        // Each time should only be recorded once
        assert!(
            self.time_of(timeout).is_none(),
            "{:?} recorded more than once",
            timeout
        );

        // There need to be at least one preceeding time recorded
        // since it follows a graph/call tree.
        let any_preceeding = timeout
            .preceeding()
            .filter_map(|to_check| self.time_of(to_check))
            .any(|_| true);

        assert!(any_preceeding, "{:?} has no preceeding", timeout);

        // Record the time
        self.times.push((timeout, self.current_time.now()));
    }

    fn time_of(&self, timeout: Timeout) -> Option<Instant> {
        self.times.iter().find(|x| x.0 == timeout).map(|x| x.1)
    }

    pub(crate) fn next_timeout(&self, timeout: Timeout) -> NextTimeout {
        let now = self.now();

        let (reason, at) = timeout
            .timeouts_to_check()
            .filter_map(|to_check| {
                let timeout = to_check.configured_timeout(&self.timeouts)?;
                // Global and PerCall record their starts. Other timestamps
                // record completion, which starts the next phase's budget.
                let time = match to_check {
                    Timeout::Global | Timeout::PerCall => self.time_of(to_check),
                    _ => to_check
                        .preceeding()
                        .filter_map(|previous| self.time_of(previous))
                        .max(),
                }
                .expect("timeout has no recorded start");
                Some((to_check, time + timeout))
            })
            .min_by(|a, b| a.1.cmp(&b.1))
            .unwrap_or((Timeout::Global, Instant::NotHappening));

        let after = at.duration_since(now);

        NextTimeout {
            after,
            reason,
            per_read: self.per_read,
            per_write: self.per_write,
        }
    }
}

#[derive(Clone)]
pub(crate) struct CurrentTime(Arc<dyn Fn() -> Instant + Send + Sync + 'static>);

impl CurrentTime {
    #[cfg(test)]
    pub(crate) fn new(now: impl Fn() -> Instant + Send + Sync + 'static) -> Self {
        Self(Arc::new(now))
    }

    pub(crate) fn now(&self) -> Instant {
        self.0()
    }
}

/// Remaining timeout and optional per-read and per-write timeouts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NextTimeout {
    /// Duration until next timeout.
    pub after: Duration,
    /// The reason reported when the remaining budget expires.
    pub reason: Timeout,
    /// Timeout for each read. See [`Self::for_read`].
    pub per_read: Option<Duration>,
    /// Timeout for each write. See [`Self::for_write`].
    pub per_write: Option<Duration>,
}

impl Default for NextTimeout {
    fn default() -> Self {
        Self {
            after: Duration::NotHappening,
            reason: Timeout::Global,
            per_read: None,
            per_write: None,
        }
    }
}

impl NextTimeout {
    /// Limit the remaining timeout by the per-read timeout.
    ///
    /// Apply at the transport performing I/O, not at layers forwarding to another transport.
    pub fn for_read(self) -> Self {
        self.capped(self.per_read, Timeout::PerRead)
    }

    /// Limit the remaining timeout by the per-write timeout.
    ///
    /// Apply at the transport performing I/O, not at layers forwarding to another transport.
    pub fn for_write(self) -> Self {
        self.capped(self.per_write, Timeout::PerWrite)
    }

    fn capped(mut self, limit: Option<Duration>, reason: Timeout) -> Self {
        if let Some(limit) = limit {
            if limit < self.after {
                self.after = limit;
                self.reason = reason;
            }
        }
        self
    }

    pub(crate) fn check(self) -> Result<Self, crate::Error> {
        if self.after.is_zero() {
            Err(crate::Error::Timeout(self.reason))
        } else {
            Ok(self)
        }
    }

    /// Returns the duration of the timeout if the timeout must happen, but avoid instant timeouts
    ///
    /// If the timeout must happen but is zero, returns 1 second
    pub fn not_zero(&self) -> Option<Duration> {
        if self.after.is_not_happening() {
            None
        } else if self.after.is_zero() {
            Some(Duration::from_secs(1))
        } else {
            Some(self.after)
        }
    }
}

impl fmt::Debug for CurrentTime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("CurrentTime").finish()
    }
}

impl Default for CurrentTime {
    fn default() -> Self {
        #[cfg(test)]
        {
            // Scheduling delays must not consume test budgets. Tests advance injected clocks.
            static NOW: std::sync::LazyLock<Instant> = std::sync::LazyLock::new(Instant::now);
            let now = *NOW;
            Self::new(move || now)
        }
        #[cfg(not(test))]
        {
            Self(Arc::new(Instant::now))
        }
    }
}

impl fmt::Display for Timeout {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let r = match self {
            Timeout::PerRead => "per read",
            Timeout::PerWrite => "per write",
            Timeout::Global => "global",
            Timeout::PerCall => "per call",
            Timeout::Resolve => "resolve",
            Timeout::Connect => "connect",
            Timeout::SendRequest => "send request",
            Timeout::SendBody => "send body",
            Timeout::Await100 => "await 100",
            Timeout::RecvResponse => "receive response",
            Timeout::RecvBody => "receive body",
        };
        write!(f, "{}", r)
    }
}
