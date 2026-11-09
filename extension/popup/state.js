// Which popup frame shows (INT-11.23, first match wins) and the marks of the
// not-reachable frame's checks (INT-11.24), from the background's state reply
// alone. Pure: tested under macOS's jsc (INT-11.43, extension/test/pure_test.js).

/**
 * The marks of INT-11.24's three checks (installed, running, integration on),
 * each "done", "failed" or "unknown": a host that answered 44 runs without
 * Larsal; 45 means Larsal runs with the integration off; anything else is no
 * host at all.
 */
export function marks(reach) {
  if (reach === 44) return ['done', 'failed', 'unknown'];
  if (reach === 45) return ['done', 'done', 'failed'];
  return ['failed', 'unknown', 'unknown'];
}

/**
 * The frame for one state reply `s` of the background (popup.status):
 * {frame, ...} with frame "not-reachable" (with `tooOld` or `marks`), "again"
 * (the session ended: read the state again), "no-vault", "locked" (with
 * `vault` and `others`), "first-connection" (with `words`, `connecting` and
 * `refused`) or "ready" (the matches frame, E7-S7f).
 */
export function choose(s) {
  const reach = s && typeof s === 'object' ? s.reach : undefined;
  if (reach === 'too-old') return { frame: 'not-reachable', tooOld: true };
  if (reach === 'ended') return { frame: 'again' };
  if (reach !== 'ok') return { frame: 'not-reachable', marks: marks(reach) };
  const vaults = Array.isArray(s.status?.vaults) ? s.status.vaults : [];
  if (!vaults.length) return { frame: 'no-vault' };
  const shown = vaults.find((v) => v.shown) ?? vaults[0];
  // The locked row comes before the error 8 row: `check` lists only unlocked vaults (INT-02.7).
  if (shown.state === 'locked') {
    return { frame: 'locked', vault: shown.name, others: vaults.filter((v) => v !== shown).map((v) => v.name) };
  }
  if (s.check?.error === 8) {
    const words = Array.isArray(s.words) ? s.words : [];
    return { frame: 'first-connection', words, connecting: s.connecting === true, refused: s.refused === true };
  }
  return { frame: 'ready' };
}
