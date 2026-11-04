use std::io::{self, Read};
use std::time;

/// Retry reads interrupted by a signal (EINTR) when a timeout applies.
///
/// Linux does not restart socket reads with SO_RCVTIMEO, even with SA_RESTART.
/// Retries use the remaining timeout; exhausted budgets return `TimedOut`.
/// Without a timeout, preserve `Interrupted` for intentional signal interruptions.
/// See <https://github.com/algesten/ureq/pull/1205> for the signal details.
pub(super) fn read_retrying_interrupts<R: Read>(
    reader: &mut R,
    buf: &mut [u8],
    timeout: Option<time::Duration>,
    mut elapsed: impl FnMut() -> time::Duration,
    mut set_timeout: impl FnMut(&mut R, time::Duration) -> io::Result<()>,
) -> io::Result<usize> {
    loop {
        match reader.read(buf) {
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {
                let Some(timeout) = timeout else {
                    return Err(e);
                };
                let left = timeout.saturating_sub(elapsed());
                if left.is_zero() {
                    return Err(io::ErrorKind::TimedOut.into());
                }
                set_timeout(reader, left)?;
            }
            result => return result,
        }
    }
}
