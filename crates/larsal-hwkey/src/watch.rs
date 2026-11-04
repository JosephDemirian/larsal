//! Looking for keys while a key list shows (INT-07.13, INT-07.14).

use crate::{Bus, Change, Detection, Reason, detect};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

/// The look starts this long after a plug-in (INT-07.14); another plug-in
/// within it moves the look on, so a key's several interfaces give one look.
const PLUG_DELAY: Duration = Duration::from_millis(500);

enum Msg {
    Change(Change),
    Again,
    Stop,
}

/// Looks for keys on its own thread while the unlock view, the wizard's key
/// part or the credential page shows (INT-07.14): once at start, 0.5 s after
/// a key is plugged in, and on [`KeyWatcher::look_again`]. A removal starts
/// no look. Requests that come in during a look fold into one more look
/// (INT-07.13); a challenge waits for a running look (the process-wide
/// lock). Each result goes to `deliver`, on the watcher's thread.
///
/// Dropping it stops the watch and joins its threads; a running look ends
/// first.
pub struct KeyWatcher {
    inbox: Sender<Msg>,
    thread: Option<JoinHandle<()>>,
}

impl KeyWatcher {
    /// Starts watching `bus`. A failure to watch plug-ins is delivered as
    /// the first result; looks on request still run.
    ///
    /// # Errors
    /// `Failed` when the thread cannot start.
    pub fn start<B>(
        bus: B,
        deliver: impl FnMut(Result<Detection, Reason>) + Send + 'static,
    ) -> Result<KeyWatcher, Reason>
    where
        B: Bus + Send + 'static,
    {
        let (inbox, messages) = mpsc::channel();
        let events = inbox.clone();
        let thread = std::thread::Builder::new()
            .name("larsal-hwkey-looks".to_owned())
            .spawn(move || {
                let mut deliver = deliver;
                let watch = bus.watch(Box::new(move |change| {
                    let _ = events.send(Msg::Change(change));
                }));
                if let Err(reason) = &watch {
                    deliver(Err(*reason));
                }
                drive(&bus, &messages, &mut deliver);
                drop(watch);
            })
            .map_err(|_| Reason::Failed)?;
        Ok(KeyWatcher {
            inbox,
            thread: Some(thread),
        })
    }

    /// "Look for keys again" (APP-06.8): a look now, or one more after the
    /// running one.
    pub fn look_again(&self) {
        let _ = self.inbox.send(Msg::Again);
    }
}

impl Drop for KeyWatcher {
    fn drop(&mut self) {
        let _ = self.inbox.send(Msg::Stop);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// The watcher's loop. `due`: when the next look runs. Messages that are
/// already waiting are taken before a look starts, and those that arrive
/// during a look set one `due` after it, so they fold into one more look.
fn drive<B: Bus>(
    bus: &B,
    messages: &Receiver<Msg>,
    deliver: &mut dyn FnMut(Result<Detection, Reason>),
) {
    // A look when the screen appears.
    let mut due = Some(Instant::now());
    loop {
        let message = match due {
            Some(at) => messages.recv_timeout(at.saturating_duration_since(Instant::now())),
            None => messages.recv().map_err(|_| RecvTimeoutError::Disconnected),
        };
        let now = Instant::now();
        match message {
            Ok(Msg::Stop) | Err(RecvTimeoutError::Disconnected) => return,
            Ok(Msg::Again) => due = Some(now),
            Ok(Msg::Change(Change::Arrived)) => {
                due = Some(match due {
                    Some(at) if at <= now => at,
                    _ => now + PLUG_DELAY,
                });
            }
            Ok(Msg::Change(Change::Removed)) => {}
            Err(RecvTimeoutError::Timeout) => {
                due = None;
                deliver(detect(bus));
            }
        }
    }
}
