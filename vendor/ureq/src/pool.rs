use std::collections::VecDeque;
use std::sync::{Arc, Mutex, Weak};
use std::{fmt, io, mem};

use http::Uri;
use http::uri::{Authority, Scheme};

use crate::Error;
use crate::config::Config;
use crate::http;
use crate::transport::time::{Duration, Instant};
use crate::transport::{Buffers, ConnectionDetails, Connector, NextTimeout};
use crate::transport::{RegisterShutdown, ShutdownHandle, Transport};
use crate::util::DebugAuthority;

pub(crate) struct ConnectionPool {
    connector: Box<dyn Connector<Out = Box<dyn Transport>>>,
    pool: Arc<Mutex<Pool>>,
}

impl ConnectionPool {
    pub fn new(connector: Box<dyn Connector<Out = Box<dyn Transport>>>, config: &Config) -> Self {
        ConnectionPool {
            connector,
            pool: Arc::new(Mutex::new(Pool::new(config))),
        }
    }

    pub fn connect(
        &self,
        details: &ConnectionDetails,
        max_idle_age: Duration,
        use_pool: bool,
    ) -> Result<Connection, Error> {
        let key = details.into();

        let mut pool = self.pool.lock().unwrap();
        if pool.closed {
            let e = io::Error::new(io::ErrorKind::NotConnected, "Agent is shut down");
            return Err(e.into());
        }
        pool.purge(details.now);

        if use_pool {
            if let Some(conn) = pool.get(&key, max_idle_age, details.now) {
                debug!("Use pooled: {:?}", key);
                return Ok(conn);
            }
        }
        drop(pool);

        let transport = self.run_connector(details)?;

        let conn = Connection {
            transport,
            key,
            last_use: details.now,
            pool: if use_pool {
                Arc::downgrade(&self.pool)
            } else {
                // An incompatible request must neither borrow from nor return
                // its newly established connection to the Agent's pool.
                Weak::new()
            },
            position_per_host: None,
        };

        Ok(conn)
    }

    pub fn run_connector(&self, details: &ConnectionDetails) -> Result<Box<dyn Transport>, Error> {
        let transport = self
            .connector
            .connect(details, None)?
            .ok_or(Error::ConnectionFailed)?;

        Ok(transport)
    }

    /// The [`RegisterShutdown`] for [`ConnectionDetails`], which tracks transports
    /// in this pool until [`shutdown()`](Self::shutdown).
    pub fn make_register_shutdown(&self) -> Arc<RegisterShutdown> {
        let pool = Arc::downgrade(&self.pool);
        Arc::new(move |handle| match pool.upgrade() {
            Some(pool) => pool.lock().unwrap().register_shutdown(handle),
            // Without the pool there is no agent left to shut down.
            None => Ok(()),
        })
    }

    /// Close every connection, idle or in use, and refuse new ones.
    ///
    /// Connections in use are shut down through the handles their connectors
    /// registered. That interrupts calls blocked on them in other threads.
    pub fn shutdown(&self) {
        let (idle, handles) = {
            let mut pool = self.pool.lock().unwrap();
            pool.closed = true;
            (
                mem::take(&mut pool.lru),
                mem::take(&mut pool.shutdown_handles),
            )
        };

        // Drop idle connections outside the lock before upgrading the handles.
        // This closes their transports and lets their weak handles expire,
        // avoiding redundant shutdown calls. Weak::upgrade skips expired handles
        // without a separate purge.
        drop(idle);

        // Shut down the remaining live transports outside the lock.
        for handle in handles.iter().filter_map(Weak::upgrade) {
            handle.shutdown();
        }
    }

    #[cfg(test)]
    /// Exposed for testing the pool count.
    pub fn pool_count(&self) -> usize {
        let lock = self.pool.lock().unwrap();
        lock.lru.len()
    }
}

pub(crate) struct Connection {
    transport: Box<dyn Transport>,
    key: PoolKey,
    last_use: Instant,
    pool: Weak<Mutex<Pool>>,

    /// Used to prune max_idle_connections_by_host.
    ///
    /// # Example
    ///
    /// If we have a max idle per hosts set to 3, and we have the following LRU:
    ///
    /// ```text
    /// [B, A, A, B, A, B, A]
    /// ```
    ///
    /// This field is used to enumerate the elements per host reverse:
    ///
    /// ```text
    /// [B2, A3, A2, B1, A1, B0, A0]
    /// ```
    ///
    /// Once we have that enumeration, we can drop elements from the front where there
    /// position_per_host >= idle_per_host.
    position_per_host: Option<usize>,
}

impl Connection {
    pub fn buffers(&mut self) -> &mut dyn Buffers {
        self.transport.buffers()
    }

    pub fn transmit_output(&mut self, amount: usize, timeout: NextTimeout) -> Result<(), Error> {
        // An already expired budget must fail here. Transports can't set a zero
        // socket timeout and would instead grant a short grace period per call.
        if timeout.after.is_zero() {
            return Err(Error::Timeout(timeout.reason));
        }
        self.transport.transmit_output(amount, timeout)
    }

    pub fn maybe_await_input(&mut self, timeout: NextTimeout) -> Result<bool, Error> {
        if timeout.after.is_zero() {
            return Err(Error::Timeout(timeout.reason));
        }
        self.transport.maybe_await_input(timeout)
    }

    pub fn consume_input(&mut self, amount: usize) {
        self.transport.buffers().input_consume(amount)
    }

    pub fn close(self) {
        debug!("Close: {:?}", self.key);
        // Just consume self.
    }

    pub fn reuse(mut self, now: Instant) {
        if !self.transport.buffers().input().is_empty() {
            // Unconsumed input means the server sent more bytes than the body
            // we read. Same condition as the probe below, only the bytes are
            // already in our buffer instead of still in the socket.
            debug!("Unconsumed input. Closing connection");
            return;
        }

        if !self.transport.is_open() {
            // The purpose of probing is that is_open() for tcp connector attempts
            // to read some more bytes. If that succeeds, the connection is considered
            // _NOT_ open, since that means we either failed to read the previous
            // body to end, or the server sent bogus data after the body. Either
            // is a condition where we mustn't reuse the connection.
            return;
        }
        self.last_use = now;

        let Some(arc) = self.pool.upgrade() else {
            debug!("Pool gone: {:?}", self.key);
            return;
        };

        debug!("Return to pool: {:?}", self.key);

        let mut pool = arc.lock().unwrap();

        if pool.closed {
            debug!("Pool shut down: {:?}", self.key);
            return;
        }

        pool.add(self);
        pool.purge(now);
    }

    pub fn is_tls(&self) -> bool {
        self.transport.is_tls()
    }

    fn age(&self, now: Instant) -> Duration {
        now.duration_since(self.last_use)
    }

    fn is_open(&mut self) -> bool {
        self.transport.is_open()
    }
}

/// The pool key is the Scheme and Authority from the uri
///
///
/// ```notrust
/// abc://username:password@example.com:123/path/data?key=value&key2=value2#fragid1
/// |-|   |-------------------------------||--------| |-------------------| |-----|
///  |                  |                       |               |              |
/// scheme          authority                 path            query         fragment
/// ```
///
/// It's correct to include username/password since connections with differing such and
/// the same host/port must not be mixed up.
///
#[derive(Clone, PartialEq, Eq)]
struct PoolKey(Arc<PoolKeyInner>);

impl PoolKey {
    fn new(uri: &Uri) -> Self {
        let inner = PoolKeyInner(
            uri.scheme().expect("uri with scheme").clone(),
            uri.authority().expect("uri with authority").clone(),
        );

        PoolKey(Arc::new(inner))
    }
}

#[derive(PartialEq, Eq)]
struct PoolKeyInner(Scheme, Authority);

#[derive(Debug)]
struct Pool {
    lru: VecDeque<Connection>,
    max_idle_connections: usize,
    max_idle_connections_per_host: usize,
    max_idle_age: Duration,
    /// Every transport the connectors created, idle or in use, until dropped.
    /// Weak, so that dropping a transport closes it as before.
    shutdown_handles: Vec<Weak<dyn ShutdownHandle>>,
    /// Set by [`ConnectionPool::shutdown()`]. No connections are made after that.
    closed: bool,
}

impl Pool {
    fn new(config: &Config) -> Self {
        Pool {
            lru: VecDeque::new(),
            max_idle_connections: config.max_idle_connections(),
            max_idle_connections_per_host: config.max_idle_connections_per_host(),
            max_idle_age: config.max_idle_age().into(),
            shutdown_handles: Vec::new(),
            closed: false,
        }
    }

    fn register_shutdown(&mut self, handle: Weak<dyn ShutdownHandle>) -> Result<(), Error> {
        // Checked under the same lock as shutdown(), so that a connection made
        // while the shutdown runs cannot escape it.
        if self.closed {
            let e = io::Error::new(io::ErrorKind::NotConnected, "Agent is shut down");
            return Err(e.into());
        }

        self.shutdown_handles.push(handle);

        Ok(())
    }

    fn purge(&mut self, now: Instant) {
        while self.lru.len() > self.max_idle_connections || self.front_is_too_old(now) {
            self.lru.pop_front();
        }

        self.update_position_per_host();

        let max = self.max_idle_connections_per_host;

        // unwrap is ok because update_position_per_host() should have set all
        self.lru.retain(|c| c.position_per_host.unwrap() < max);

        // Evicting idle connections can expire their shutdown handles.
        self.shutdown_handles.retain(|h| h.strong_count() > 0);
    }

    fn front_is_too_old(&self, now: Instant) -> bool {
        self.lru.front().map(|c| c.age(now)) > Some(self.max_idle_age)
    }

    fn update_position_per_host(&mut self) {
        // Reset position counters
        for c in &mut self.lru {
            c.position_per_host = None;
        }

        loop {
            let maybe_uncounted = self
                .lru
                .iter()
                .rev()
                .find(|c| c.position_per_host.is_none());

            let Some(uncounted) = maybe_uncounted else {
                break; // nothing more to count.
            };

            let key_to_count = uncounted.key.clone();

            for (position, c) in self
                .lru
                .iter_mut()
                .rev()
                .filter(|c| c.key == key_to_count)
                .enumerate()
            {
                c.position_per_host = Some(position);
            }
        }
    }

    fn add(&mut self, conn: Connection) {
        self.lru.push_back(conn)
    }

    fn get(&mut self, key: &PoolKey, max_idle_age: Duration, now: Instant) -> Option<Connection> {
        while let Some(i) = self.lru.iter().position(|c| c.key == *key) {
            let mut conn = self.lru.remove(i).unwrap(); // unwrap ok since we just got the position

            // Before we release the connection, we probe that it appears to still work.
            if !conn.is_open() {
                // This connection is broken. Try find another one.
                continue;
            }

            if conn.age(now) >= max_idle_age {
                // A max_duration that is shorter in the request than the pool.
                // This connection survives in the pool, but is not used for this
                // specific connection.
                continue;
            }

            return Some(conn);
        }
        None
    }
}

impl fmt::Debug for ConnectionPool {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConnectionPool")
            .field("connector", &self.connector)
            .finish()
    }
}

impl fmt::Debug for Connection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Connection")
            .field("key", &self.key)
            .field("conn", &self.transport)
            .finish()
    }
}

impl fmt::Debug for PoolKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PoolKey")
            .field("scheme", &self.0.0)
            .field("authority", &DebugAuthority(&self.0.1))
            .finish()
    }
}

impl<'a, 'b> From<&'a ConnectionDetails<'b>> for PoolKey {
    fn from(details: &'a ConnectionDetails) -> Self {
        PoolKey::new(details.uri)
    }
}
