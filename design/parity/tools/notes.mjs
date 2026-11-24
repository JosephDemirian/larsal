// Design parity (Verify): the lead's decisions and the Verify notes that
// compare.mjs reads. RULES classify a mockup string that the app shows
// differently: `live` values match by format only; the others are known
// differences the lead accepted (spec/decisions.md). `larsal` is the pattern the
// app's counterpart must match, so an accepted string is still checked.

const LEVEL_MOCKUP = /^(Strong|Weak|Fair|Very weak|Medium)$/;
const LEVEL_APP = /^(Excellent|Good|Poor|Weak|Very poor|Fair)$/;

// E5-S5 built states-unsaved-changes and states-delete-as-a-sheet (2026-10-28).
// E9-S2 built dialogs-ssh-key-use (2026-10-28). E5-S8 built
// dialogs-weak-vault-password and dialogs-create-key-file (2026-10-28). E5-S10
// built dialogs-changed-on-disk, dialogs-close-with-unsaved-changes and
// dialogs-save-failed (2026-10-28). E8-S2 built menubar-auto-type-picker
// (2026-10-28). The other dialogs of the section belong to later stories.
export const LATER = {
  'dialogs-export-warning': 'E5-S11 (FEA-09)',
  'dialogs-import': 'E5-S11 (FEA-08)',
  'dialogs-browser-asks-for-an-entry': 'E7',
  'dialogs-connect-a-browser': 'E7',
};

export const RULES = [
  // E5-S7 reports (Verify 2026-10-28): card words and live values of the
  // Personal demo vault, limited to the section's frames (LD-208, LD-163 (4)).
  ...[
    { f: 'health-check', why: 'Weak KPI: FEA-05.4, below Good is a score under 75', ref: 'FEA-05.4, LD-208', test: (m) => m === 'under 40 bits', app: /^under 75 bits$/ },
    { f: 'health-check', why: 'FEA-05.13 MSG-HC-REUSED after the FEA-05.6 strength reason', ref: 'FEA-05.6, FEA-05.13, LD-163 (4)', test: (m) => /^Reused \S+ uses the same password\.$/.test(m), all: [/^Reused$/, /^(Very easy|Somewhat easy) to guess\. Same password on \d+ entries\.$/] },
    { f: 'health-check', why: 'FEA-05.4 level and FEA-05.6 reason (the card\'s estimate of the demo password)', ref: 'FEA-05.4, FEA-05.6, LD-163 (4)', test: (m) => m === 'Weak Short and built from a common word and a year.', all: [/^(Poor|Weak|Bad)$/, /^(Very easy|Somewhat easy) to guess\.$/] },
    { f: 'health-check', why: 'FEA-05.14 MSG-HC-EXPIRED after the FEA-05.6 strength reason', ref: 'FEA-05.6, FEA-05.14, LD-163 (4)', test: (m) => /^Expired This password expired on \w+ \d+\.$/.test(m), all: [/^Expired$/, /Past its expiry date\.$/] },
    { f: 'health-check', live: true, why: 'the FEA-05 estimate of the demo password in whole bits', ref: 'LD-166', test: (m) => /^\d+ bits$/.test(m), app: /^\d+ bits$/ },
    { f: 'health-check', why: 'healthy count by the card rules: 21 passwords − 7 rows', ref: 'FEA-05.15, LD-163 (4)', test: (m) => /^15 other passwords are strong, unique and current\./.test(m), app: /^14 other passwords are strong, unique and current\. Entries you exclude are listed under the ⋯ menu\.$/ },
    { f: 'statistics', live: true, why: 'size of the demo file', ref: 'LD-166', test: (m) => m === '84 KB', app: /^[\d.]+ (B|KB|MB)$/ },
    { f: 'statistics', live: true, why: 'the demo file\'s key derivation in the words of APP-07 M07-07 (Memory in MiB, Iterations)', ref: 'APP-07 M07-07, LD-166', test: (m) => m === 'AES-256 · Argon2id, 64 MiB, 1 s', app: /(^|, )AES-256 · Argon2id, \d+ MiB, \d+ iterations?$/ },
    { f: 'statistics', live: true, why: 'attachments of the demo vault\'s live entries (3, 1.7 KB)', ref: 'LD-166, LD-208 (5)', test: (m) => m === '4 · 2.3 KB', app: /(^|, )\d+ · [\d.]+ (B|KB|MB)$/ },
    { f: 'statistics', why: 'FEA-07.12: the average length is a whole number', ref: 'FEA-07.12, LD-163 (4)', test: (m) => m === '18.6 characters', app: /^\d+ characters?$/ },
    { f: 'passkeys', why: 'a table row read together in the mockup\'s innerText; each cell is its own element', ref: 'mockup `tr`', test: (m) => m === 'alex-dev password one-time code Oct 22 Remove', all: [/^alex-dev$/, /^password$/, /^one-time code$/, /^Oct 22$/, /^Remove$/] },
    { f: 'browser', why: 'a table row read together; hosts sorted (the editor\'s site access list, E5-S5), the card names no order', ref: 'INT-02.32, mockup `tr`', test: (m) => m === 'github.com gist.github.com — fill, no submit', all: [/^github\.com$/, /^gist\.github\.com$/, /^—$/, /^fill, no submit$/] },
  ].map(({ f, ...r }) => ({ ...r, frames: [`reports-reports-${f}`] })),
  // E5-S8 (2026-10-28), limited to its frames; first, so a wider rule of
  // another frame (the unlock screen's "Browse…") never takes these strings.
  ...[
    ['New vault', /^New Vault$/, 'APP-07 M07-01 window title'],
    ['The name shows in the sidebar and on the lock screen.', /^The name shows in the vault list\. Name and description stay editable in Vault Settings\.$/, 'APP-07 M07-03 step 1 line'],
    ['The defaults suit almost everyone. They match what security reviews recommend today.', /^Choose how long an unlock takes\. /, 'APP-07 M07-05 step 2 line'],
    ['Choose a password', /^Password and keys$/, 'APP-07 step 3 title (Steps table)'],
    ['You need it to open the vault. Larsal cannot recover it.', /^Choose what opens this vault\. Only you should know it or have it\.$/, 'APP-07 M07-09 step 3 line'],
    ['Repeat it', /^Verify password$/, 'APP-07 M07-10 repeat label'],
    ['••••••••••••••••••', /^orchid-meteor-pine-quartz-41$/, 'APP-07.11: Show shows both fields together'],
    ['A second secret kept in a file. Without it the vault does not open.', /^Keep this file exactly as it is, and keep a copy somewhere safe: the vault opens only with this file, unchanged\.$/, 'APP-07 M07-12 key file note'],
    ['Create…', /^New Key File…$/, 'APP-07 M07-12 button'],
    ['Choose…', /^Choose Key File…$/, 'APP-07 M07-12 button'],
    ['Create vault', /^Create Vault$/, 'APP-07 M07-14 button'],
    ['Hide', /^Hide password$/, 'APP-07 M07-10 eye button name'],
    ['Generate', /^Generate password$/, 'APP-07 M07-10 dice button name'],
  ].map(([m, app, why]) => ({ why: `${why} (card words over mockup)`, ref: 'BUILD-AND-VERIFY order 2, LD-163 (4); E5-S8 report', frames: ['vault-new-vault-step-1', 'vault-new-vault-step-2', 'vault-new-vault-step-3'], test: (x) => x === m, app })),
  { live: true, why: 'MasterKeyChanged of the test copy', frames: ['vault-vault-settings-security'], test: (m) => /^Changed \w{3} \d{1,2}, \d{4}$/.test(m), app: /^Changed [A-Z][a-z]{2} \d{1,2}, \d{4}$/ },
  { why: 'security key row: E10 control, drawn and disabled; no key', ref: 'LD-163', frames: ['vault-vault-settings-security'], test: (m) => /^YubiKey .* · slot \d · challenge-response$/.test(m), app: /^Not used$/ },
  { live: true, why: 'file version and size of the test copy', frames: ['vault-vault-settings-general'], test: (m) => /^Version 4\.\d · \d+ KB$/.test(m), app: /^Version 4\.[01] · [\d.]+ (B|KB|MB)$/ },
  { live: true, why: 'history of the demo vault (MOD-03.7 sizes)', frames: ['vault-vault-settings-history'], test: (m) => /^[\d.]+ KB in \d+ versions$/.test(m), app: /^[\d.]+ (B|KB|MB) in \d+ versions?$/ },
  { why: 'connected browser: the vault stores when it was connected (INT-02 _CREATED_), no last use', ref: 'MOD-12.18, INT-02; E5-S8 report', frames: ['vault-vault-settings-browser-keys'], test: (m) => /^Connected \w{3} \d{1,2} · last used /.test(m), app: /^Connected [A-Z][a-z]{2} \d{1,2}$/ },
  ...[
    ['This password is easy to guess', /^This password is easy to guess, so your vault is less safe\. Use it anyway\?$/],
    ['“family2026” could be guessed in about 2 hours on a graphics card. Anyone with a copy of the vault file could open it.', /^This password is easy to guess, so your vault is less safe\. Use it anyway\?$/],
    ['Use It Anyway', /^Use this password$/],
    ['Choose Another', /^Cancel$/],
  ].map(([m, app]) => ({ why: 'FEA-05.20 MSG-MK-WEAK with ACT-MK-USE-WEAK and Cancel (default); no password on screen (rule 4)', ref: 'FEA-05.20, BUILD-AND-VERIFY order 2; E5-S8 report', frames: ['dialogs-weak-vault-password'], test: (x) => x === m, app })),
  { why: 'APP-07.13: the new key file is named "<vault name>.larsalkey"', ref: 'APP-07.13; E5-S8 report', frames: ['dialogs-create-key-file'], test: (m) => m === 'family.larsalkey', app: /^Family\.larsalkey$/ },
  // E5-S10 (2026-10-28): the cards' messages and buttons over the mockup's words.
  ...[
    ['dialogs-changed-on-disk', 'Another app saved it at 10:24, after you opened it. You have 2 changes that are not saved yet.', /^“Personal\.larsalvault” was changed by another program, and this vault has unsaved changes\.$/, 'APP-05.27 MSG-DISK-UNSAVED'],
    ['dialogs-changed-on-disk', 'Reload', /^Discard$/, 'APP-05.27 button Discard'],
    ['dialogs-changed-on-disk', 'Keep mine', /^Ignore$/, 'APP-05.27 button Ignore'],
    ['dialogs-changed-on-disk', 'Decide Later', /^Cancel$/, 'APP-05.27 button Cancel'],
    ['dialogs-close-with-unsaved-changes', 'Save changes to “Personal” before closing?', /^Personal was changed\. Save the changes\?$/, 'APP-02.15 step 8 MSG-LOCK-SAVE'],
    ['dialogs-close-with-unsaved-changes', 'Don’t Save', /^Discard$/, 'APP-02.15 step 8 button Discard'],
  ].map(([f, m, app, why]) => ({ why: `${why} (card words over mockup)`, ref: 'BUILD-AND-VERIFY order 2, LD-163 (4); E5-S10 report', frames: [f], test: (x) => x === m, app })),
  // Live values: format only.
  { live: true, why: 'live one-time code', test: (m) => /^\d{3} \d{3}$/.test(m), app: /^\d{3} \d{3}$/ },
  { live: true, why: 'live countdown', test: (m) => /^\d{1,2} s$/.test(m), app: /^\d{1,2} s$/ },
  { live: true, why: 'live countdown', test: (m) => /^New code in \d{1,2} s$/.test(m), app: /^New code in \d{1,2} s$/ },
  { live: true, why: 'save time of the demo file', test: (m) => /^Saved at \d\d:\d\d · encrypted$/.test(m), app: /^Saved at \d\d:\d\d · encrypted$/ },
  { live: true, why: 'lock time of this session', test: (m) => /^Locked at \d\d:\d\d$/.test(m), app: /^Locked at \d\d:\d\d$/ },
  {
    live: true, why: 'vault path: the test copies the demo vaults to target/option-a/Passwords', test: (m) => /^~\/.*\/[A-Z][a-z]+\.larsalvault$/.test(m),
    app: (m) => new RegExp(`^~/.*/Passwords/${m.split('/').pop().replace('.', '\\.')}$`),
  },
  { live: true, ref: 'LD-166', why: 'save state of the demo file (the app says "Saved just now" only for a file saved in this session)', test: (m) => m === 'Saved just now · encrypted', app: /^Saved (just now|at \d\d:\d\d) · encrypted$/ },
  { live: true, ref: 'LD-166', why: 'SSH key fingerprint, computed from the demo vault\'s key (the mockup\'s is drawn)', test: (m) => /^SHA256:[A-Za-z0-9+/]{43}$/.test(m), app: /^SHA256:[A-Za-z0-9+/]{43}$/ },
  // Accepted differences (lead).
  { why: 'lock footer reason: comes with E6-S2\'s idle lock', ref: 'LD-166, LD-169', test: (m) => /^Locked at \d\d:\d\d after \d+ minutes without use$/.test(m), app: /^Locked at \d\d:\d\d$/ },
  { why: 'needs-attention reason text from the card (FEA-05)', ref: 'LD-163 (4), LD-169', test: (m) => /^(Reused|Weak|Expired) password\./.test(m), app: /^(Reused|Weak|Expired|Poor) password\..+/ },
  { why: 'card number shows dots only (AGENTS.md rule 4)', ref: 'rule 4', test: (m) => /^•••• •••• •••• \d{4}$/.test(m), app: /^•••• •••• •••• ••••$/ },
  { why: 'SSH agent row: comes with E9 (Load key drawn and disabled)', ref: 'LD-163, LD-169', test: (m) => m === 'Loaded' || m === 'Removed when the vault locks', app: /^Load key$/ },
  { why: 'FEA-05.4 strength level (card words)', ref: 'LD-163 (4)', test: (m) => LEVEL_MOCKUP.test(m), app: LEVEL_APP },
  {
    why: 'FEA-05.4 level and the FEA-05 estimate (bits from the card estimator, characters from LD-164)', ref: 'LD-163 (4), LD-164, LD-166',
    test: (m) => /^(Strong|Weak|Fair|Very weak|Reused|Expired) · \d+ characters · about \d+ bits$/.test(m),
    app: /^(Excellent|Good|Poor|Weak|Very poor|Fair|Reused|Expired) · \d+ characters · about \d+ bits$/,
  },
  { why: 'APP-06 UL-TITLE "Unlock <name>"', ref: 'LD-163 (4)', test: (m) => /^(Personal|Work|Family) is locked$/.test(m), app: (m) => new RegExp(`^Unlock ${m.split(' ')[0]}$`) },
  { why: 'APP-04.15 "Use password instead"', ref: 'LD-163 (4)', test: (m) => m === 'Use vault password instead', app: /^Use password instead$/ },
  { why: 'key file row: the test\'s key file in the card\'s form "name · folder" (UL-KEY)', ref: 'LD-163 (2), (4)', test: (m) => /\.larsalkey · /.test(m), app: /^key-hex64\.larsalkey · ~\/.+$/ },
  { why: 'key file row: the card\'s button "Browse…" (UL-KEY)', ref: 'LD-163 (2), (4)', test: (m) => m === 'Change…' || m === 'Choose…', app: /^Browse…$/ },
  { why: 'key file row: the card\'s placeholder "No key file" (UL-KEY)', ref: 'LD-163 (2), (4)', test: (m) => m === 'None', app: /^No key file$/ },
  { why: 'security key row: E10 control, drawn and disabled; no key chosen', ref: 'LD-163', test: (m) => /^YubiKey .* · serial \d+ · slot \d$/.test(m), app: /^Not used$/ },
  { why: 'APP-06 UL-PW placeholder "Password"', ref: 'LD-163 (4)', test: (m, kind) => kind === 'placeholder' && m === 'Vault password', app: /^Password$/ },
  { why: 'welcome source-available label and the live version', ref: 'LD-163 (5), LD-345', test: (m) => /^Version \d+\.\d+ · source available$/.test(m), app: /^Version \d+\.\d+\.\d+ · source available$/ },
  { why: 'needs-attention count by the card rules (7, mockup 6)', ref: 'LD-163 (4)', test: (m) => m === '6' || /6 need attention$/.test(m), app: /^(7|\d+ entries · 7 need attention|Password health, 7 need attention|Needs attention, 7)$/ },
  // E5-S5 editor and sheets (LD-192 (3), (5); LD-167; data of the demo vault).
  { why: 'FEA-05.4 strength words and the card estimator in the editor\'s password label', ref: 'LD-192 (5), LD-163 (4)', test: (m) => /^Password · (Strong|Weak|Fair|Very weak), about \d+ bits$/.test(m), app: /^Password · (Excellent|Good|Fair|Poor|Weak|Very poor|Bad), about \d+ bits$/ },
  { why: 'passkey row in the card\'s words "‹RP ID› · ‹passkey user name›" (no stored time)', ref: 'LD-192 (5), INT-04.51, D-INT04-15', test: (m) => /^github\.com · alex-dev · added \w+ \d+$/.test(m), app: /^github\.com · alex-dev$/ },
  { why: 'protected custom value shows dots only', ref: 'AGENTS.md rule 4, MOD-01.6', test: (m) => /^ghp_•+$/.test(m), app: /^•+$/ },
  { why: 'attachment limit in the card\'s words (MOD-05.16: 1 GiB)', ref: 'LD-192 (3)', test: (m) => /up to 10 MB each$/.test(m), app: /up to 1 GB each$/ },
  { why: 'the card\'s words for the Auto-Type switch', ref: 'LD-167', test: (m) => m === 'Auto-Type for this entry', app: /^Let Auto-Type use this entry$/ },
  { why: 'the card\'s words for the hide option', ref: 'LD-167, INT-02.29', test: (m) => m === 'Hide this entry from the browser', app: /^Never offer this entry to browsers$/ },
  { why: 'the demo vault\'s SSH key (comment and key line are data; a key no one holds)', ref: 'LD-166, testdata/README.md', test: (m) => m === 'alex@macbook' || /^ssh-ed25519 \S+ alex@macbook$/.test(m), app: /^(alex@morgan-labs|ssh-ed25519 \S+ alex@morgan-labs)$/ },
  { why: 'history size computed from the demo vault (MOD-03.7)', ref: 'LD-192 (5)', test: (m) => /^3 versions · [\d.]+ KB$/.test(m), app: /^3 versions · [\d.]+ KB$/ },
  { why: 'the card\'s history limit words (MOD-03.6: the size limit is per entry)', ref: 'LD-192 (5)', test: (m) => m === 'Larsal keeps the last 10 versions of each entry, up to 6 MB per vault.', app: /^Larsal keeps the last 10 versions of each entry, up to 6 MB per entry\.$/ },
  { why: 'the two action buttons of a table row, read together in the mockup\'s innerText', ref: 'mockup `td.act`', test: (m) => m === 'Show Restore', all: [/^Show$/, /^Restore$/] },
  { why: 'the two action buttons of a table row, read together in the mockup\'s innerText', ref: 'mockup `td.act`', test: (m) => m === 'Open Save…', all: [/^Open$/, /^Save…$/] },
  { why: 'the discard sentence names the draft\'s real changes', ref: 'LD-192 (5)', test: (m) => m === 'You changed the password and added one tag.', app: /^You changed .+\.$/ },
  { why: 'clone labels in the card\'s words', ref: 'LD-192 (5), MOD-10.1', test: (m) => m === 'Add “ - Clone” to the title', app: /^Mark the copy's title with ' - Clone'$/ },
  { why: 'clone labels in the card\'s words', ref: 'LD-192 (5), MOD-10.1', test: (m) => m === 'Link username and password to the original', app: /^Link user name and password to the original$/ },
  { why: 'setup title in the card\'s words', ref: 'LD-192 (5), FEA-04.22', test: (m) => m === 'Add a one-time code', app: /^Set up one-time password$/ },
  { why: 'MI04-34 in the card\'s words', ref: 'LD-192 (5), INT-04.46', test: (m) => m === 'Remove the passkey for github.com?', app: /^Remove the passkey\?$/ },
  { why: 'MI04-34 in the card\'s words', ref: 'LD-192 (5), INT-04.46', test: (m) => /^You can no longer sign in to github\.com with it\. The password and the one-time code stay\.$/.test(m), app: /^You can no longer sign in to github\.com with it\. The password stays\.$/ },
  {
    why: 'copy notice in the card\'s words, APP-03.21 MSG-COPIED "<label> copied. Clears in <N> s."; N is Larsal\'s clear delay (10 s, APP-03 settings; the mockup draws 30)',
    ref: 'APP-03.21, BUILD-AND-VERIFY order (card over mockup); known difference for the lead (E6-S1)', frames: ['states-copied'],
    test: (m) => m === '· clipboard clears in 30 s', app: /^Password copied\. Clears in \d+ s\.$/,
  },
  // E5-S9 settings (Verify 2026-10-28): card words over the mockup, limited to the section's frames.
  ...[
    ['Save after every change', /^Save changes as you make them$/, 'S-FILE-01 "Shown as"; W-04 asks the owner to change the mockup text', 'LD-167, APP-01 S-FILE-01'],
    ['Asks GitHub once a day. Nothing else leaves this Mac.', /^Asks GitHub once a week\. Nothing else leaves this Mac\.$/, 'S-START-09 "Check for updates once a week" and APP-01.19 (next check now + 7 days); off by default, drawn disabled until E14', 'APP-01.19, D-01-2'],
    ['{DB_FILENAME}.old.larsalvault', /^\{FILE_NAME\}\.old\.larsalvault$/, 'S-FILE-06 Larsal default with the APP-05.20 token', 'APP-01.2, APP-05.20'],
  ].map(([m, app, why, ref]) => ({ why: `${why} (card words over mockup)`, ref: `BUILD-AND-VERIFY order 2; ${ref}`, frames: ['settings-settings-general'], test: (x) => x === m, app })),
  // E5-S6 generator: the value and its bits are made live (BUILD-AND-VERIFY: generated passwords match the format).
  { live: true, why: 'generated password: 20 printable characters, one of each chosen type at least (FEA-02.8)', frames: ['generator-generator-in-the-window', 'generator-password'], test: (m) => /^[A-Za-z0-9]{20}$/.test(m), app: /^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[^A-Za-z0-9])[\x21-\x7e]{20}$/ },
  { live: true, why: 'generated passphrase: 5 words of the built-in list joined with "-"', frames: ['generator-passphrase'], test: (m) => /^[a-z]+(-[a-z]+){4}$/.test(m), app: /^[a-z]+(-[a-z]+){4}$/ },
  { live: true, why: 'strength of the live value in whole bits (FEA-05 estimate, FEA-03.7 formula)', frames: ['generator-generator-in-the-window', 'generator-password', 'generator-passphrase'], test: (m) => /^\d+ bits$/.test(m), app: /^\d+ bits$/ },
  // E5-S11 Verify (2026-10-28): the window item of the menu bar icon's menu.
  { why: 'APP-08.21 action.toggle_window: "Show Window" while the window is hidden, minimized or behind, "Hide Window" while in front (card words over mockup)', ref: 'APP-08.21, LD-214 (2), BUILD-AND-VERIFY order 2', frames: ['menubar-menu-bar-icon'], test: (m) => m === 'Show Larsal', app: /^(Show|Hide) Window$/ },
];

// Per frame: Verify notes (summary lines in the report), the smallest fix
// for a FAIL, colours accepted after inspection (colourOk), and extra fails
// found by eye (fails).

// Notes for the run after the Builder's fix pass (LD-169). Each frame keeps
// only what the measurements need: its fixed theme, the view behind an open
// menu, the recorded shifts (geoShift: boxes in the area move by exactly dy;
// what is left must stay within 2 pt), proof of a drawn letter tile (drawn).
const LIVE = 'Live, format only: codes, countdowns, the save and lock times, the test copies\' paths; LD-166: the FEA-05 bits, the SSH fingerprint, "Saved just now".';
const LATERS = 'Controls of later stories are drawn and disabled with their story in the help text (LD-163); their behaviour waits for those stories.';
const MENUS = 'Closing menus with Escape or a click outside: Mac QA on a real screen (LD-166).';

const E5S5 = 'Accepted (LD-192 (5)): card and data over the mockup where the rules above name them; LD-167 wordings.';

const E5S6 = 'Built by E5-S6. The value and its bits are live (format only). The strength word is FEA-05.4\'s level of the live value (passphrase: FEA-03.7\'s 64.62 bits for 5 words is Weak, the mockup draws Strong; LD-163 (4)); the bar is coloured by that level (FEA-05.5) on the mockup\'s 130-bit scale.';

export const NOTES = {
  // E5-S9 settings (Verify 2026-10-28).
  'settings-settings-general': { summary: ['Built by E5-S9. Card words over the mockup: "Save changes as you make them" (LD-167, W-04), "once a week" (APP-01.19), "{FILE_NAME}.old.larsalvault" (APP-01.2). Check for updates and Include beta versions drawn and disabled until E14 (D-01-2: off, nothing is sent). Open Larsal at login goes through the LoginItem protocol (SMAppService; tests use a fake). Option A draws no OK or Cancel: closing the window is OK, Escape is Cancel (APP-01.3).', LATERS] },
  'settings-settings-security': { summary: ['Built by E5-S9. Unlock with Touch ID (E6-S3) and the capture switch (APP-10, E6-S5, never stored) drawn and disabled. The stored values reach the copy countdown, the lock timers and the search timer (Verify driver).', LATERS] },
  'settings-settings-auto-type': { summary: ['Built by E5-S9. Values stored under their APP-01 keys; Auto-Type reads them in E8; Change (the shortcut recorder) drawn and disabled. The mockup\'s row words stay until INT-05\'s mockup change (LD-167, D-INT05-12).', LATERS] },
  'settings-settings-browser-integration': { summary: ['Built by E5-S9. Every row follows "Let browsers use Larsal" (APP-01.5); the browser boxes write their setup files with E7 (INT-01.8), Safari waits for signing (INT-01.15). "Use my own proxy program" (LD-167) sits below the frame\'s fold, as the mockup\'s row does.', LATERS] },
  'settings-settings-ssh-agent': { summary: ['Built by E5-S9. The status row is the frame\'s (a fake probe in tests; the user\'s agent is never asked). "Use a different socket" waits for W-05.', LATERS] },
  'settings-settings-shared-groups': { summary: ['Built by E5-S9. The identity is the frame\'s data; the key pair comes with E11 (D-01-6: Keychain, never in a settings file or export).', LATERS] },
  'settings-settings-shortcuts': {
    runSkip: ['⌘⌫'],
    summary: ['Built by E5-S9. "⌘⌫" (Delete Entry) is 4 pt wider than drawn, right edge equal, y within 0.5 pt: the bundled IBM Plex Sans 400 (the mockup\'s own file) has no ⌘, ⇧ or ⌫ glyph, so Chrome and Core Text each fall back to a system face; every ⌘ run is 1 to 1.5 pt wider for the same reason and ⌫ adds 2.5 pt. Read-only list (APP-01.29\'s shortcut dialog is not drawn).'] },
  // E5-S7 reports (Verify 2026-10-28).
  'reports-reports-health-check': {
    runSkip: ['Aug 27', 'Jul 21'],
    drawn: { A: 'proof/amazon-tile-<theme>.png', S: 'proof/slack-tile-<theme>.png' },
    summary: ['Built by E5-S7. Card over mockup (LD-208, LD-163 (4)): 7 rows by the card rules, sorted by health score (FEA-05.16), so Zalando (score 0) leads and the Amazon and eBay rows sit one row (57.5 pt) lower, x equal; pill words are FEA-05.4 levels, reasons FEA-05.6, FEA-05.13, FEA-05.14; the Weak KPI says "under 75 bits" (FEA-05.4) and the footer counts 14 (21 − 7). The letter tiles "A" and "S" are drawn and kept out of the tree (proof/amazon-tile-<theme>.png, proof/slack-tile-<theme>.png).', LIVE] },
  'reports-reports-breach-check': { summary: ['Built by E5-S7. The frame\'s results are set as the screen state (the online check itself runs in Rust tests against a fake service; nothing leaves this Mac). Card over mockup: FEA-06.9 exposure bands in the Seen column, the count in its help; "Check with a downloaded list instead" drawn and disabled (the offline check is the command line tool, FEA-06.14). Before a press the page shows the consent text (FEA-06.1, LD-208 (4), W-12).', LIVE] },
  'reports-reports-statistics': { summary: ['Built by E5-S7. Live values of the demo copy: size, key derivation (1 MiB, 2 iterations), 3 attachments. Card over mockup: Groups 8 counts the root (FEA-07.2), average length a whole number (FEA-07.12). The FEA-07 rows the frame lacks wait for W-12 (LD-208 (5)).', LIVE] },
  'reports-reports-passkeys': {
    runSkip: ['alex-dev', 'one-time code', 'Oct 22', 'alex.morgan@icloud.com', 'Oct 21', '@alex@mastodon.social', 'passkey only', 'Sep 18', 'alex@morgan-labs.dev', 'password', 'Sep 15'],
    summary: ['Built by E5-S7. Card over mockup: rows sorted by title (INT-04.52), so GitHub and Apple Account, Mastodon and Linear change places; each moved text run sits exactly one row (58 to 60 pt) up or down with x within 1 pt. "Added" is the entry\'s last change (LD-208 (6)).', LIVE] },
  'reports-reports-browser': {
    runSkip: ['—', 'www.figma.com'],
    drawn: { A: 'proof/amazon-browser-tile-<theme>.png' },
    summary: ['Built by E5-S7. Card over mockup: rows in title order (INT-02.32), so Amazon leads and the runs move one row (58 to 59.5 pt), x equal; GitHub\'s hosts are sorted (gist.github.com before github.com), the card names no order. The "A" tile is drawn (proof/amazon-browser-tile-<theme>.png).', LIVE] },
  'generator-generator-in-the-window': { summary: [E5S6 + ' The popover sits under the toolbar button (top 118, right 166) over the main window; Generator, ⌥⌘G, a click outside and Escape close it; the value goes on close and lock (D-02-5).', LIVE, LATERS] },
  'generator-password': { summary: [E5S6 + ' The popover alone, 404 × 340.', LIVE] },
  'generator-passphrase': { summary: [E5S6 + ' The popover alone, 404 × 368; the snapshot keeps a phrase that takes two lines, as drawn.', LIVE] },
  'editor-editor-history': { runSkip: ['changed'], geoShift: [{ x0: 480, y0: 360, dy: 53, ref: 'LD-192 (5): MOD-03.11 lists the current entry and every item, one row more than drawn' }], summary: ['The pill word "changed" stands in two rows and is matched to the first; both rows are drawn alike.', E5S5, LIVE] },
  'editor-editor-advanced': { runSkip: ['Drop files here, or'], summary: ['The drop line in the card\'s words is shorter, so its centred text starts 4.3 pt further right (LD-192 (3)).', 'Custom fields sorted by name (MOD-01, LD-192 (5)); the API token shows dots only (rule 4).', E5S5] },
  'editor-editor-ssh-agent': { summary: ['The demo key\'s line and comment are data; the agent settings come with E9.', E5S5, LIVE] },
  'states-delete-as-a-sheet': { behind: ['states-needs-attention'], summary: ['With the sheet open only the sheet is in the tree; names behind it are found on the same view without it (states-needs-attention).', E5S5] },
  'dialogs-one-time-code-as-qr': { mask: [[22, 112, 416, 206], [22, 336, 346, 40]], summary: ['The QR symbol is the live one; dark modules on a light panel in both themes (LD-192 (4)); the panel and the added countdown and Copy of the card (FEA-04.23, LD-192 (5)) are masked for pixels and colours, nothing else (LD-199 (8)).'] },
  'dialogs-wi-fi-as-qr': { mask: [[22, 92, 416, 206]], summary: ['The QR symbol is the live one; dark modules on a light panel in both themes (LD-192 (4)); the panel is masked for pixels and colours, nothing else (LD-199 (8)).'] },

  'lock-locked-touch-id': { summary: ['Accepted: "Unlock Personal" (APP-06 UL-TITLE) and "Use password instead" (APP-04.15), LD-163 (4); the footer reason comes with E6-S2 (LD-166, LD-169). Window buttons are drawn by macOS (accepted).', LIVE, LATERS] },
  'lock-locked-password-key-file-security-key': { summary: ['Accepted: "Unlock Personal", placeholder "Password", key file row in the card\'s words with the test\'s key file, security key row of E10 drawn disabled (LD-163 (2), (4)); footer reason with E6-S2; empty field after a failed unlock (APP-06.11, LD-166). The Yubico logo now carries its name.', LIVE, LATERS] },
  'lock-locked-vault-switcher': { behind: ['lock-locked-password-key-file-security-key'], summary: ['Vault menu and its 9 items at 0 pt difference. With the menu open only the menu is in the tree; names behind it are found on the same view without the menu.', 'Accepted as in the password frame; footer reason with E6-S2.', MENUS] },
  'lock-welcome': { summary: ['Accepted: license line with the live version (LD-163 (5)). Recent paths are live.', LATERS] },
  'main-main-window-light': { fixedTheme: 'light', summary: ['Keeps its own light theme in both sets. Accepted: FEA-05.4 levels, the attention count 7, the FEA-05 estimate (LD-163 (4), LD-166). Rows below the fold are clipped in the mockup and built lazily in the app.', LIVE, LATERS, MENUS] },
  'main-main-window-dark': { fixedTheme: 'dark', behaviourFrom: 'main-main-window-light', summary: ['The dark twin of main-main-window-light (own dark theme in both sets); behaviour cites the light frame\'s tests (same view).', LIVE, MENUS] },
  'states-needs-attention': {
    geoSkip: ['row:'],
    geoShift: [{ x0: 919, y0: 345, dy: 17.5, ref: 'LD-169: the card\'s reason text wraps one more line' }],
    drawn: { S: 'proof/slack-tile-<theme>.png' },
    summary: ['Accepted: the 7th entry heads the list, so the mockup\'s rows sit 91 pt lower (LD-163 (4), LD-166; rows not judged); the card\'s reason text and level (LD-169). The reason wraps to two lines (35.5 pt against one line of 17), so the actions and fields below move 17.5 pt; after that shift every box and text run there is within 0.6 pt.', 'The Slack letter tile "S" is drawn but kept out of the tree like every letter tile; text recognition missed the single letter, the crop shows it (proof/slack-tile-light.png, proof/slack-tile-dark.png); "A" of the same tile code was read.', LIVE] },
  'states-card': { summary: ['Accepted: card number in dots only (rule 4), levels and count from the card; Visa Debit has a letter tile (logos by URL host only).', LIVE, LATERS] },
  'states-server-with-ssh-key': {
    colourOk: ['#ffedea', '#2c1517'],
    geoShift: [
      { x0: 919, y0: 310, y1: 571, dy: 77.5, ref: 'LD-169: the card\'s Weak notice (66 pt block and its 11.5 pt gap)' },
      { x0: 919, y0: 571, dy: 16.5, ref: 'LD-169: the notice minus the E9 SSH agent row (77.5 − 61)' },
    ],
    summary: ['Accepted (LD-169): the card\'s estimator rates the passphrase Weak, so the attention notice appears (the extra --neg-bg area); the SSH agent row ("Loaded", "Removed when the vault locks") comes with E9. Fields between the notice and the agent row move 77.5 pt, fields after it 16.5 pt (77.5 − the mockup\'s 61 pt agent row); after those shifts every box and text run is within 0.6 pt. Header and buttons are within 2 pt.', 'The fingerprint is computed from the demo key (format only, LD-166).', LIVE, LATERS] },
  'states-wi-fi': { summary: ['Levels from the card.', LIVE, LATERS] },
  'states-favorites-tags-open': { summary: ['Tags open with the five tags; levels from the card.', LIVE, LATERS] },
  'states-search-tips': { summary: ['All seven tips with their words (is:weak wording from FEA-01.17, accepted).', LIVE, LATERS] },
  'states-search-with-no-result': { summary: ['The empty result keeps its frame and the one-line message.', LIVE] },
  'states-more-menu': { behind: ['main-main-window-light'], summary: ['Menu and its 11 items within 2 pt; items of later stories disabled with the reason. Strings behind the menu are found on main-main-window-light.', LIVE, MENUS] },
  'states-vault-switcher': { behind: ['main-main-window-light'], summary: ['Menu and items within 2 pt; Lock Personal and Work act (tests).', LIVE, MENUS] },
  'states-sort-menu': { behind: ['main-main-window-light'], geoSkip: ['button:Title'], summary: ['Sort menu within 2 pt; Title and the order marked. The header\'s "Title" button lies under the open menu and is not compared.', LIVE, MENUS] },
  'states-copied': { summary: ['Built by E6-S1. Copy password (rail, field button, entry menu, ⌘C) copies in Rust; the value never reaches the screen layer. Known difference, card over mockup: APP-03.21 "Password copied. Clears in 10 s." for the mockup\'s "Password copied · clipboard clears in 30 s" (10 s is Larsal\'s clear delay); the box is narrower for the shorter words (about 245 against 301 pt, centred on the same x); its place (centred, 20 above the foot), height 40, radius 10, --primary fill, ink, glyph and shadow are as drawn. The notice goes after 2.6 s, as in the mockup.', LIVE, LATERS] },
  'states-recycle-bin': { summary: ['Restore, Delete forever and Empty Recycle Bin drawn and disabled (E5-S10). The X logo now carries its name.', LIVE, LATERS] },
  'states-new-empty-vault': { summary: ['The three first steps drawn and disabled until their stories. Save line: live (the demo file has a save time).', LATERS] },
  // E5-S8 (2026-10-28).
  'vault-new-vault-step-1': { colourOk: ['#e2eff2', '#10303a'], summary: ['Built by E5-S8. The Name field has the focus with "Family" selected as the step appears (APP-07.5): its accent ring and soft halo are drawn; the mockup draws no focus. The window buttons are the real ones (masked). Card words: M07-01, M07-03.', LIVE] },
  'vault-new-vault-step-2': { mask: [[36, 200, 648, 23], [36, 288, 648, 22]], geoShift: [{ x0: 0, y0: 180, y1: 640, dy: 20, ref: 'APP-07 M07-05: the card\'s step line takes two lines' }], summary: ['Built by E5-S8. Recommended is simple mode at 1.0 s (APP-07.6); Custom shows the drawn rows editable plus Parallel threads (APP-07.7). Card words: M07-05 (two lines, so the choices sit 20 pt lower; in dark the moved accent fill is most of the changed pixels).', 'Accepted (LD-210, Verify E5-S8 round 2): only the two strips where the Recommended card\'s accent fill moved (x 36 to 684; y 200 to 223 and 288 to 310 pt: the card is 200 to 290 pt drawn, 221 to 309.5 pt in the app) are masked for pixels and colours. With the 20 pt shift undone (the app\'s rows 200 to 660 pt moved up), the whole frame differs 1.72 % (light) and 1.66 % (dark).'] },
  'vault-new-vault-step-3': { colourOk: ['#e2eff2', '#10303a'], geoSkip: ['button:Create…', 'button:Choose…'], geoShift: [{ x0: 0, y0: 470, y1: 640, dy: 16, ref: 'APP-07 M07-12: the card\'s key file note takes two lines' }], summary: ['Built by E5-S8. The Password field has the focus as the step appears (APP-07.11). Show shows both fields (APP-07.11), so the repeat is in clear. Card words: step title, M07-09, M07-10, M07-12, M07-14; the key file buttons are wider for M07-12\'s "New Key File…" and "Choose Key File…", so their boxes are not compared. Security key and Touch ID drawn and disabled (E10, E6-S3).', LIVE, LATERS] },
  'vault-vault-settings-general': { summary: ['Built by E5-S8. Each control applies itself (no Apply drawn); the path is the test copy\'s.', LIVE] },
  'vault-vault-settings-security': { summary: ['Built by E5-S8. The key file is a new one the test made (personal.larsalkey); encryption Argon2id 64 MiB, 2 threads, 1.0 s. Security key and Touch ID drawn and disabled (E10, E6-S3). The unlock time slider is linear from 0.1 to 5 s (APP-07.6), so its thumb sits at 18 % (drawn at 40 %).', LIVE, LATERS] },
  'vault-vault-settings-recycle-bin': { summary: ['Built by E5-S8. "Empty entries older than" has no card rule yet: drawn and disabled with the reason.', LATERS] },
  'vault-vault-settings-history': { summary: ['Built by E5-S8 on the demo vault\'s history.', LIVE] },
  'vault-vault-settings-browser-keys': { summary: ['Built by E5-S8: the demo vault\'s two associations and four entries with site permissions; Disconnect and Remove all… ask first.', LIVE] },
  'dialogs-weak-vault-password': { geoSkip: ['button:Use It Anyway', 'button:Choose Another', 'dialog:This password is easy to'], summary: ['Built by E5-S8: FEA-05.20 MSG-MK-WEAK in the dialog look, one sentence as the title, so the sheet is shorter than drawn; it never names the password (rule 4).', 'Accepted (LD-210, Verify E5-S8 round 2): the sheet is 44 pt shorter (x, y and width equal); both buttons sit 44 pt higher, "Use this password" keeps the drawn left edge (25 pt wider) and Cancel the drawn right edge (59 pt narrower). These three boxes are not compared. The image sizes differ (460 × 148 against 460 × 192 pt), so pixels and colour shares are not measured; icon, title style and button styles were checked by eye.'] },
  'dialogs-create-key-file': { summary: ['Built by E5-S8: APP-07.13\'s "<vault name>.larsalkey".'] },
  // E5-S10 (2026-10-28).
  'dialogs-changed-on-disk': { geoSkip: ['button:Decide Later'], summary: ['Built by E5-S10: APP-05.27 (the vault has unsaved changes) with the card\'s message and buttons in the mockup\'s choice rows; the drawn descriptions stay. The same sheet asks APP-05.26 (Load, Keep), APP-05.28 (Merge then save, Discard, Overwrite) and APP-05.30 (Overwrite). Rust decides by checksum; the folder and file watch raises it (AT-I05 test).'] },
  'dialogs-close-with-unsaved-changes': { geoSkip: ['button:Don’t Save'], summary: ['Built by E5-S10: APP-02.15 step 8 MSG-LOCK-SAVE for Close Vault, Lock and Quit when the save on lock is off or failed; Save saves again, Discard lets the vault go, Cancel keeps it.'] },
  // E5-S11 Verify (2026-10-28).
  'menubar-menu-bar-icon': { summary: ['Built by E5-S11. The live menu is a native NSMenu that macOS draws (APP-08.24, APP-08.25, LD-214 (2)); the snapshot is MenuBarIconFrame (test code) drawing that NSMenu\'s items, keys, badges and enabled states with Option A\'s menu parts over the mockup\'s desktop and bar, so its pixels prove the items, not macOS\'s own menu look (Mac QA).', 'Accepted (LD-214 (1)): the drawn menu bar reads Larsal, File, Edit, View, Vault, Entry, the real SwiftUI order (Apple HIG: app menus after View); the mockup draws View after Entry.', 'The status item itself is never added in tests (FakeSlot; NoStatusSlot in a hidden launch); the icon on a real menu bar is Mac QA (owner\'s go).'] },
  // E8-S2 Builder (2026-10-28), for the lead.
  'menubar-auto-type-picker': { colourOk: ['#e2eff2', '#10303a'], summary: ['Built by E8-S2. The search field has the keyboard focus as the picker appears (INT-05.26): its accent ring and soft halo are drawn, as on vault-new-vault-step-1; the mockup draws no focus. The snapshot is AutoTypePickerFrame (test code): the mockup\'s desktop with the real AutoTypePickerView over the Personal demo vault plus the frame\'s "GitHub (work bot)" entry, with GitHub\'s second window rule left out in memory so the list holds the frame\'s two rows. ⏎ is drawn in the system font, as the mockup\'s font stack falls back to it.', 'Not drawn until the owner\'s mockup changes (W-06): the app name under the header (D-INT05-16 (3)), the small line\'s sequence and vault additions, the empty list MI05-45 and the row menu MI05-44 (D-INT05-16 (4)), and R05-6\'s hint line; MI05-43 stays as drawn.'] },
  'dialogs-save-failed': { summary: ['Built by E5-S10: APP-05.13 MSG-SAVE-FAILED as the mockup\'s sheet; the reason is the system\'s (the snapshot shows the mockup\'s demo reason). Save As… (APP-05.6), Close, Try Again.'] },
};

export const COMMANDS = `Run from the project root on 2026-10-28, in this order. No window was opened: Chrome ran headless, the app views rendered in borderless windows at x −20000 that were never ordered front, and the test process is not a hosted app.

1. \`node design/option-a/tools/export-reference.mjs\` (reference images and manifest from the current mockup)
   → \`light: 91 frames\`, \`dark: 91 frames\`, \`manifest.json: 91 frames\` (5 min 23 s).
2. \`npm install --prefix /tmp/parity-tools pixelmatch pngjs\` → \`added 2 packages\`; versions pixelmatch 8.0.0, pngjs 7.0.0 (outside the project).
3. \`scripts/build-core.sh\` → \`build-core (debug): target/larsal-core/LarsalFFI.xcframework and target/larsal-core/Swift/LarsalCore.swift\`, exit 0.
4. \`DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild -project macos/Larsal.xcodeproj -scheme Larsal -destination platform=macOS -derivedDataPath target/xcode test -skip-testing:LarsalUITests SWIFT_TREAT_WARNINGS_AS_ERRORS=YES\` (the check.sh G2 test step)
   → \`✔ Suite SnapshotTests passed\`, \`✔ Suite ParityLockTests passed\`, \`✔ Suite ParityMainTests passed\`, \`✔ Suite ParityStatesTests passed\`, \`✔ Suite ScreenTests passed\`, \`✔ Suite ParityFontTests passed\`, \`✔ Test run with 41 tests in 10 suites passed after 30.276 seconds\`, \`** TEST SUCCEEDED **\`. SnapshotTests wrote larsal-shots/<theme>/<frame-id>.png and, new for this check, the accessibility tree next to each (\`<frame-id>.ax.json\`, test only). The Parity suites are new (test only, 27 tests): they press the mockup's controls through the accessibility tree. Log: target/parity/behaviour.log.
5. \`swift format lint --strict macos/LarsalTests/*.swift\` and \`swiftlint lint --strict --quiet LarsalTests/\` (in macos/) → no findings.
6. \`node design/parity/tools/mockup-dom.mjs lock,main,states\` (mockup boxes, text runs, fonts, glyphs, controls; headless) → \`light: 21 frames, 2586 text runs\`, \`dark: 21 frames, 2586 text runs\`.
7. \`swift design/parity/tools/ocr.swift larsal-shots/light/*.png larsal-shots/dark/*.png\` (on-device text recognition, only for strings kept out of the accessibility tree) → 36 images read.
8. \`node design/parity/tools/compare.mjs <section>\` (pixelmatch threshold 0.1, includeAA false; text, tokens, geometry, behaviour; writes this report).

Measured looks (LD-169): \`ParityFontTests\` (new, test only). "Font check" reads the large code's font runs from the accessibility tree and compares the drawn glyphs of the large code and a row code with the same string set by Core Text in IBM Plex Mono 500 and in the system face. "Focus check" renders the focused row offscreen in light and dark and reads the outline back. A probe in /tmp showed that the font runs in the tree name the requested font even where the glyphs drawn differ, so the glyph comparison is the deciding check.

E6-S1 re-run (Builder, 2026-10-28, sections lock, main and states; states-copied added): steps 1, 2 and 6 were not repeated (mockup.js and app.css are older than the reference images and target/parity/dom-*.json).
3. \`scripts/build-core.sh\` → \`build-core (debug): target/larsal-core/LarsalFFI.xcframework and target/larsal-core/Swift/LarsalCore.swift\` (bindings with \`copyField\`, \`clearClipboard\`, \`Copied\`).
4. The check.sh G2 test step as above → \`✔ Suite SnapshotTests passed\`, \`✔ Suite ParityStatesTests passed\`, \`✔ Test run with 45 tests in 10 suites passed after 32.980 seconds\`, \`** TEST SUCCEEDED **\`. New: the states-copied snapshot and three "Parity states-copied" tests. The offscreen windows are now pinned to sRGB: on 2026-10-28 the Mac's screen gave Display P3 renders (accent #1b6c80 read as 53,107,126), which failed the Focus check and would shift every colour; the reference images are sRGB. Log: target/parity/behaviour.log.
7. \`swift design/parity/tools/ocr.swift larsal-shots/light/*.png larsal-shots/dark/*.png\` → 38 images read.
8. \`node design/parity/tools/compare.mjs lock\` → \`lock: 4/4 PASS\`; \`node design/parity/tools/compare.mjs main\` → \`main: 2/2 PASS\`; \`node design/parity/tools/compare.mjs states\` → \`states: 13/13 PASS\` (states-copied light 1.57 %, dark 1.6 %).

E6-S1 second pass (Builder, 2026-10-28, LD-181): larsal-ffi \`copy_code\` and \`copy_fingerprint\`; Copy One-Time Code (⌘T), the code row's Copy and Copy fingerprint work; the unlock form's shown password is an AppKit field whose own field editor has no Copy or Cut (APP-03.19).
3. \`scripts/build-core.sh\` → bindings with \`copyCode\` and \`copyFingerprint\`.
4. The check.sh G2 test step → \`✔ Test run with 47 tests in 10 suites passed after 30.581 seconds\`, \`** TEST SUCCEEDED **\`; general pasteboard change count 10124 before and after the run. Log: target/parity/behaviour.log.
7. OCR as above → 38 images read.
8. \`node design/parity/tools/compare.mjs lock\`, \`main\`, \`states\`: counts in each report's result line.

E6-S1 Checker fix (Builder, 2026-10-28): the shown password's editor matches the system's password editor (no writable pasteboard types, no single- or multi-type selection write, no Services send, no drag, no Writing Tools, no corrections, replacements or completion, a context menu of Paste, Delete, Select All only). Test moved to ShownPasswordFieldTests.swift with a plain text view as control.
4. The G2 test step with \`-derivedDataPath /tmp/e6s1/dd\` → \`✔ Test run with 47 tests in 11 suites passed after 31.305 seconds\`, \`** TEST SUCCEEDED **\`; general pasteboard change count 10124 before and after. Log: target/parity/behaviour.log.
8. \`node design/parity/tools/compare.mjs lock\` → result line of design/parity/lock/report.md.`;
