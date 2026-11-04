# INT-03 URL matching

Status: reviewed (LD-189, LD-191)
Epics: E7-S3 (checks: AT-F05); used by E7-S2 and E7-S4 (INT-02.13 step 4, INT-02.19), E7-S5 (INT-04.8 and INT-04's public suffix test), and the entry editor's website rows (E5-S5)
Parity rows: SI-03 (and SI-05 for the public suffix list INT-04 shares)

## What it does

When a page asks for sign-ins, App decides which entries **fit** the page and in which order to offer them. An entry fits when one of its URLs names the page's site: the same scheme (an option, on by default), the same port, and the page's host equal to the entry's host or below it, inside the same registrable domain (the part of a name one owner can register, found with the Public Suffix List). Paths never decide whether an entry fits; they only rank it. Additional URLs may also be an exact URL in quotes or a pattern with `*`. A host the user allowed for the entry fits too (INT-02.16).

Then App ranks the fitting entries: an exact URL first, then the same URL without its query, then a parent folder, then the same host, then a parent host.

Neighbor cards: INT-02 (what happens with fitting entries; the allowed hosts), INT-01 (the page URLs the extension sends), INT-04 (passkeys: the relying party field counts as an additional URL, INT-04.8; the public suffix test of INT-04.11 uses this card's list), MOD-01.8 (additional URL field names), MOD-08 (placeholders and references in URLs; MOD-08.9's URL parts and host encoding), MOD-02.17 (the group option that ignores a leading `www`), APP-01 (S-BRW-11, S-BRW-12), INT-05.22 (Auto-Type's own URL test, which is a different, looser rule).

Public standards a Builder needs: the WHATWG URL Standard (how browsers serialize the page URL: lower-case scheme and host, ASCII hosts, default ports dropped, IPv4 and IPv6 forms); RFC 3492 (Punycode) and RFC 5890 (IDNA names, the `xn--` prefix); the Public Suffix List (publicsuffix.org, its format and its "formal algorithm", ICANN and private sections); RFC 6761 and RFC 2606 (the reserved demo names used in the tests).

## Inputs and outputs

**In:** the page URL `url`, the top page `top_url` and the form URL `form_url` (INT-01.27); an entry's main URL, its additional URL fields, its passkey relying party field; its site access item's allowed hosts (INT-02.16); the group option `BrowserOmitWww` (MOD-02.17); S-BRW-11 match scheme (on), S-BRW-12 best matches only (off).

**Out:** for each entry: fits or not, and a rank from 0 to 100; for each host: its registrable domain (used by INT-02.19 and INT-04.11).

**Limits:**

| Limit | Value | Rule |
|---|---|---|
| Page URL | 8,192 bytes (INT-01.25) | INT-03.1 |
| One entry URL after resolving | 2,048 characters; longer never fits | INT-03.17 |
| URLs looked at per entry | 64: the main URL, then additional URLs in INT-03.2's order | INT-03.17 |
| `*` per pattern | 16; more never fits | INT-03.17 |
| Labels in a host pattern that holds `*` | 10; more never fits (MI03-01; F-245, LD-326 (2)) | INT-03.11, INT-03.17 |
| Host | DNS limits: labels of at most 63 octets, a host of at most 253, after encoding (LD-112) | INT-03.4 |

## Rules

### The page

INT-03.1 **Reading the page URL.** The extension sends `url` as the browser serialized it (WHATWG URL Standard). App reads scheme, host, port, path and query from it, with the same host reading as entry URLs (INT-03.4). Only `http`, `https` and `file` pages take part; any other scheme (`chrome:`, `about:`, `data:`, an extension's own pages), an `http` or `https` URL without a valid host, or a URL App cannot read: `logins.find` and `logins.get` answer error 14 (INT-01.40) and nothing fits. The page's **effective port** is its port, else 443 for `https` and 80 for `http`. The fragment and user info are ignored everywhere.

### Entry URLs

INT-03.2 **Which URLs an entry has.** In this order:
1. The main `URL` field. It is resolved (MOD-08) only when it holds a reference (MOD-08.24); otherwise it is used as stored, so other placeholders in it stay as text and the URL does not fit (INT-03.3). Reference: the same.
2. The additional URLs: every custom field whose name starts with `KP2A_URL` (MOD-01.8), always resolved (MOD-08 table: "Additional URLs: always resolved"): `KP2A_URL` first, then `KP2A_URL_` followed by a number by that number ascending, then the other names starting with `KP2A_URL` by name.
3. The passkey relying party field `KPEX_PASSKEY_RELYING_PARTY` (INT-04.8), always resolved.
Empty values are skipped. History items have no URLs for matching.

INT-03.3 **Reading one entry URL.**
- ASCII spaces and tabs at both ends are removed.
- Additional URLs only: a value that starts and ends with `"` is a **quoted exact URL** (INT-03.11); a value that holds `*` is a **pattern** (INT-03.11). In the main URL, `"` and `*` have no meaning: a main URL holding `*` never fits.
- A value without `://` is read as if `https://` stood in front (`example.com/login` → `https://example.com/login`), except a value that starts with letters, digits, `+`, `-` or `.` up to a `:` followed by anything but a digit (`mailto:alex@example.com`, `tel:`, `data:`): that is another scheme and never fits (`localhost:3000` and `example.com:8443/x` are hosts with ports). Reference: the same when S-BRW-11 is on; with it off its scheme does not matter either; its URL reader also takes `mailto:` and the like as schemes.
- Schemes: `http` and `https` fit web pages; `file` fits only file pages (INT-03.13); any other scheme (`cmd://`, `ftp://`, `ssh://`, the reference's vault-opening scheme) never fits.
- A value holding a space inside, or any of `<`, `>`, `^`, `` ` ``, `{`, `|`, `}` anywhere, never fits (reference; so an unresolved placeholder never fits). After the ends are trimmed, a value holding any other white space or a control character (a tab or newline inside, a non-ASCII space) never fits either (App's own rule, fail closed; LD-322 (3)).
- User info and the fragment are ignored. An empty path counts as `/`.

INT-03.4 **Hosts.** Every host, from the page, an entry URL, a pattern's fixed labels or an allowed host, is compared in one form:
- one trailing `.` is removed (LD-119 accepts it);
- ASCII letters are lower-cased; a label with non-ASCII characters is lower-cased and encoded with Punycode behind `xn--`, exactly as MOD-08.9 does for `{URL:HOST}` (LD-58);
- the DNS limits of LD-112 apply after encoding; an empty label (`a..b`), a label or host over the limits, or a character outside letters, digits, `-` and `_` makes the host invalid, and a URL with an invalid host never fits;
- **IPv4**: when the last label is all digits, the host must be four decimal numbers 0 to 255 without leading zeros, separated by `.`; any other form (`192.168.001.001`, `0x7f.1`, `3232235777`) is invalid. Browsers rewrite such forms in the page URL already; App does not guess what an entry meant;
- **IPv6**: inside `[` `]`, compared as its 16 bytes (`[::1]` equals `[0:0:0:0:0:0:0:1]`); a bracketed text that is not IPv6 is invalid (LD-119).
App does no other Unicode mapping (D-INT03-5): an entry host typed in decomposed form or with full-width letters does not equal the browser's host and does not fit.

### When an entry URL fits

INT-03.5 **Scheme** (S-BRW-11, on). On: the entry URL's scheme must equal the page's (`https` with `https`, `http` with `http`). Off: `http` and `https` fit each other. Reference: the same.

INT-03.6 **Port** (D-INT03-2). When the entry URL names a port, the page's effective port must equal it. When it names none, the page's effective port must be the default port of the page's scheme (443 for `https`, 80 for `http`). So `https://example.com` fits `https://example.com/` but not `https://example.com:8443/`, and `https://example.com:443` fits `https://example.com/`. Reference difference: it compares ports only when the entry names one, and compares that port with the page's written port, so an entry without a port fits every port (AT-F05 "other ports" fails there) and `https://example.com:443` fits nothing.

INT-03.7 **Host.** With H the entry host and P the page host (INT-03.4 form):
- H is an IP address: P must equal H.
- H has one label (`localhost`, `nas`, `router`): P must equal H.
- Otherwise: P must equal H or end with `.` followed by H (whole labels only), **and** the registrable domain of P (INT-03.10) must exist and equal that of H. So `example.com` fits `mail.example.com` and `a.b.example.com`; `mail.example.com` does not fit `example.com`; `b.example.com` does not fit `ab.example.com`. An entry host that is itself a public suffix (`co.uk`, or the private suffix `github.io`) has no registrable domain, so it fits no page at all, not even its own host.
Reference differences: it tests "P ends with H" as plain text, so `b.example.com` fits its sibling `ab.example.com` (D-INT03-3); it treats a public suffix as its own base domain, so an entry `https://github.io` fits the page `https://github.io/` there; it compares base domains computed from its own URL parser's host form.

INT-03.8 **Path, query, fragment.** They never decide whether a plain entry URL fits. `https://example.com/login` fits `https://example.com/other`. They only rank (INT-03.14). Reference: the same.

INT-03.9 **Ignore a leading `www`** (group option `BrowserOmitWww`, MOD-02.17). When the entry's group resolves the option on and H starts with the label `www`, that first label is removed before INT-03.7 and INT-03.14 (so `https://www.example.com` fits `https://example.com/` and its subdomains, and ranks as `https://example.com`), only when what is left has a registrable domain (INT-03.10); otherwise H is kept (`www.example`, `www.co.uk`, `www.github.io`; F-246, LD-326 (3)). Only the first label is removed. Reference difference: it removes every `www.` text inside the host, so `www.mywww.example.com` becomes `myexample.com`.

INT-03.10 **Registrable domain** (D-INT03-1). The registrable domain of a host is found with the Public Suffix List's formal algorithm, using both its ICANN and its private sections, with the list's default rule (an unlisted last label is a public suffix): the public suffix plus one more label to its left. A host that is itself a public suffix has none. IP addresses and one-label hosts have none (INT-03.7 handles them by equality). Examples: `mail.example.com` → `example.com`; `a.b.bank.co.uk` → `bank.co.uk`; `user.github.io` → `user.github.io`; `a.b.example` → `b.example` (unlisted last label `example`); `co.uk` → none. The same function serves INT-02.19 and INT-04.11. Bitwarden uses the same list with its private section (the `tldts` library with private domains on); the reference uses the copy built into its UI toolkit.

INT-03.11 **Quoted exact URLs and patterns** (additional URLs only; D-INT03-4).
- **Quoted exact**: the text between the quotes, without its fragment, must equal `url` without its fragment and user info, character for character (reference; App drops the fragment on both sides, as INT-03.3 ignores it everywhere: F-234, LD-322 (2)). Empty quotes or a `*` inside never fit. A quoted exact URL fits by its text alone, also on a host that is a public suffix (`"https://github.io/"` fits only that page): it names one page, so it cannot reach another site (LD-322 (2)).
- **Patterns**: the value is read like any entry URL (INT-03.3), then:
  1. Never fits (MI03-01 in the editor): only `*` characters; `**`; `*.*`; a `*` in the scheme or the port; a `*` in an IPv6 address; a label holding `*` and a non-ASCII character; more than 16 `*`; or a host pattern (other than an IPv4 pattern, step 3) whose **fixed tail** has no registrable domain inside it. The fixed tail is the labels to the right of the last label that holds `*`; it must be a valid host whose registrable domain (INT-03.10) exists and ends the tail. `*.example.com` and `sub.*.example.com` pass (tail `example.com`); `*.com`, `*.co.uk`, `*.github.io`, `example.*` never fit. A host pattern holding `*` with more than 10 labels never fits (INT-03.17's table; F-245). A pattern whose host holds no `*` (`https://localhost:3000/*`, `http://192.168.1.1/admin/*`) compares its host by equality: a host that is a public suffix (`https://github.io/*`) never fits (MI03-01, as INT-03.7), and an IP address or a one-label host fits only itself (LD-322 (3)).
  2. Scheme and port: as INT-03.5 and INT-03.6.
  3. Host, compared label by label from the right, the whole host: a label that is exactly `*` stands for one or more whole labels; a label with `*` among other characters stands for one label in which each `*` matches zero or more characters (`app-*` fits `app-eu`). Fixed labels must be equal. For IPv4: two to four parts, each a number or `*`, the first not `*`; each `*` stands for one or more numbers, and the page address must have four (`127.128.*` fits `127.128.129.130`; `127.160.*.2` fits `127.160.8.2`).
  4. Path: an empty path or `/` fits every path. Any other path must match the page's whole path, where `*` matches any run of characters, `/` included, and other characters match themselves; the pattern's path is first percent-encoded as the WHATWG URL Standard encodes paths, and the hex digits of `%` escapes compare without letter case. The query and fragment are ignored.
  5. The page's registrable domain (INT-03.10) must equal the fixed tail's registrable domain. Step 1 alone does not ensure this: the list can hold a private suffix below the tail's registrable domain, and a page under that suffix belongs to another site (F-230, LD-322 (2)).
- **No regular expressions.** App reads no regular expression from a URL field. Patterns come from a vault, which may be hostile; the `*` patterns above run in linear time (INT-03.17). Reference difference: it turns patterns into regular expressions that are not anchored and skips its registrable domain test for them, so `https://*.example.com` fits `https://x.example.com.attacker.example/` and `https://*.com/*` fits every `.com` site (found by reading the source; V-INT03-1).

INT-03.12 **Allowed hosts** (D-INT02-8). A host in the entry's site access Allow list (INT-02.16) fits a page whose host equals it (INT-03.4 form), whose scheme is `https` (S-BRW-11 on) or `http` or `https` (off), and whose effective port is the default of its scheme. It does not fit subdomains. A denied host never fits (INT-02.17). Reference difference: its Allow list only skips the question and never makes an entry fit.

INT-03.13 **File pages.** When the page's scheme is `file`, an entry fits only when one of its URLs, after resolving and trimming, equals `url` exactly; nothing else fits a file page, and `file` URLs never fit web pages. Reference: its extension sends `file://` as the page URL and the real file URL as the form URL, and it compares with that; App's extension sends the real file URL as `url`.

### Order

INT-03.14 **Rank.** For a fitting entry, App rates each of its URLs that fits and takes the highest rate. A URL whose scheme differs from P's rates 0, checked first (reference); otherwise its rate is the first row from the top that holds. With P the page URL and F the form URL (both without fragment and user info), and E the entry URL as fitted (INT-03.3, INT-03.9; empty path as `/`):

| Rate | When |
|---|---|
| 100 | E equals P or F: scheme, host, effective port, path and query; or a quoted exact URL fits; or a file page fits |
| 90 | E equals P or F without the query |
| 85 | E's path is a parent folder of P's or F's path: same scheme, host and effective port, and the page path is longer and starts with E's path, where E's path ends with `/` or the next page character is `/` |
| 80 | E's host equals P's host; or an allowed host fits (INT-03.12) |
| 70 | E's host equals F's host |
| 60 | P's host is below E's host |
| 50 | F's host is below E's host |
| 40 | a pattern fits |
| 0 | E's scheme differs from P's (possible only with S-BRW-11 off) |

Reference differences: quoted exact URLs and patterns rate 0 there (its rater cannot read them; D-INT03-6); hosts without a dot other than `localhost` rate 0 there (D-INT03-8); "below" is a plain text suffix there.

INT-03.15 **Best matches only** (S-BRW-12, off). On: only the entries with the highest rank are offered. Reference: the same.

INT-03.16 **Order of equal ranks** (D-INT03-7). Higher rank first; equal ranks in vault order (INT-02.10), then group tree order (a group, then its subgroups depth-first, the root first), then the group's stored entry order. Reference difference: equal ranks come out in the reverse of its search order.

### Limits and the editor

INT-03.17 **Bounds.** An entry URL longer than 2,048 characters after resolving never fits; App looks at no more than 64 URLs per entry (INT-03.2's order); patterns are matched with a linear-time method (a plain `*` matcher over the bounded lengths, or the approved `regex-automata` crates, LD-110), never a backtracking engine; the page's registrable domain is computed once per request, and each entry host's once for each URL read (LD-322 (5)); the Public Suffix List lookup walks only as many of a host's suffixes as the longest rule has labels (F-245). One work meter and one entry index per request pay and find every resolution of entry URLs (LD-126 (1), (3)); when the meter runs out, a URL that holds a placeholder is read as stored and never fits (F-244, LD-326 (1)). Matching one page against 10,000 entries with 4 URLs each finishes in under 200 ms in a release build on this Mac, also with page and entry hosts at the DNS limit of INT-03.4 and with hostile references and patterns (F-244, F-245). Known limit: a hostile vault of 10,000 entries with 64 URLs each takes about 1 to 2.2 s for one page, and the time grows with the vault (LD-326 (2)). Also inside the known limit, at about 0.3 s each for 10,000 entries with 4 URLs: patterns whose 10 labels are `*` label runs against a page host at the DNS limit, and entry URLs near 2,048 characters that fit (F-252, LD-328).

INT-03.18 **Website rows in the editor.** The entry editor's website rows (frame `editor-editor-entry`: "Website", "+ Add another website") add and edit additional URLs. A new row gets the name `KP2A_URL`, or `KP2A_URL_` with the first unused number from 1 (MOD-01.8). Rows show in INT-03.2's order; the passkey field is not a row (it shows on the passkey line). Under a row App shows a note when the value can never fit a web page: MI03-01 (a refused pattern), MI03-02 (no valid host), MI03-03 (another scheme). A value holding a reference gets no note (it is resolved when matched). The frame's note "gist.github.com is also allowed" lists the allowed hosts (INT-02.29). Notes never stop the save.

INT-03.19 **The public suffix list's age** (D-INT03-1). App ships the list inside its build and never downloads it (no network, Rust rule 12). Each App release takes the newest list version available at its build. A suffix added to the list after App's build is treated by the default rule; INT-03.7's whole-label rule keeps one tenant's entries from fitting another tenant's site even then.

### Messages

App's own wording; IDs are ours.

| ID | Kind | Rule | App text |
|---|---|---|---|
| MI03-01 | note | INT-03.11 | This pattern can't be used: a `*` may not stand for a whole domain or its ending. Use a pattern like https://*.example.com. |
| MI03-02 | note | INT-03.4 | This is not a website address App can match. |
| MI03-03 | note | INT-03.3 | Browsers only get entries for http and https addresses. |

## Edge cases and errors

- **Entry URL with a placeholder in the main field** (`https://{S:host}/`): not resolved, holds `{`: never fits (reference). Put it in an additional URL, which is resolved.
- **Main URL holding a reference to another entry's URL:** resolved first, then matched (MOD-08).
- **A reference that cannot be resolved:** the text stays as stored and holds `{`: never fits.
- **Entry `example.com/login` and S-BRW-11 off:** read as `https://example.com/login`; fits `http://example.com/` too, rank 0 there.
- **The page is `https://example.com.` with a trailing dot:** the dot is removed before comparing (INT-03.4).
- **Internationalized hosts:** `https://bücher.example` fits `https://xn--bcher-kva.example/`. The prompt shows the ASCII form (LD-58).
- **Mixed-script lookalikes:** `exаmple.com` with a Cyrillic `а` is `xn--exmple-4nf.com` and never equals `example.com`.
- **A user's own entry for a whole hosting suffix** (`https://github.io`): never fits; the user must name their own site (`https://name.github.io`).
- **Entry host `localhost` and page `https://localhost:3000/`:** fits only when the entry names port 3000 (INT-03.6).
- **Two entries fit equally:** INT-03.16.
- **Entry with 10,000 additional URL fields** (hostile vault): only 64 are looked at.
- **Page URL with credentials** (`https://u:p@example.com/`): browsers do not send them in this form any more; App ignores user info anyway.

## Lead decisions

| ID | Question | Options | Recommended, with evidence |
|---|---|---|---|
| D-INT03-1 | Source of the Public Suffix List | (a) the `psl` crate (list compiled into code, new release about weekly, MIT or Apache-2.0, 37 million downloads; observed on crates.io 2026-10-28: version 2.1.245 of 2026-10-23), pinned and re-pinned for each App release, with an AT-J03 review; (b) App's own small matcher over a copy of the list file (MPL-2.0 data); (c) no list, last two labels only | (a). Every proven tool uses the real list: browsers ship it; Bitwarden uses `tldts` with private domains; the reference uses its toolkit's copy. (c) is wrong for `co.uk` and `github.io`. (a) avoids writing a parser for the list's wildcard and exception rules. Approved crate table gains one row after AT-J03 |
| D-INT03-2 | Ports (INT-03.6) | (a) the page's effective port must equal the entry's (default port when the entry names none); (b) reference: ports compared only when the entry names one | (a). AT-F05 requires "other ports: no fill"; a browser origin includes the port (WHATWG), and Bitwarden's "Host" match includes the port. Cost: an entry without a port that was used on a non-default port stops fitting; the user adds the port, or fills once through search and Remember |
| D-INT03-3 | Subdomains (INT-03.7) | (a) whole labels only; (b) plain text suffix, as the reference | (a). With (b) an entry for `b.example.com` fits `ab.example.com`, a sibling that may belong to someone else on shared hosts (AT-F05 "attacker subdomains") |
| D-INT03-4 | Patterns (INT-03.11) | (a) anchored `*` patterns, linear time, a registrable domain required in the fixed tail at match time; (b) reference: unanchored regular expressions, no registrable domain test, the tail rule only as an editor colour | (a). (b) lets `https://*.example.com` fit `x.example.com.attacker.example` and `*.com` fit every `.com` site (V-INT03-1). Patterns keep the reference's forms, so existing vaults keep working for every honest pattern |
| D-INT03-5 | Internationalized hosts (INT-03.4) | (a) MOD-08.9's encoding (lower case, Punycode), no other mapping; (b) add the `idna` crate for full UTS #46 processing as browsers do | (a). Browsers already send the page host in ASCII; only entry hosts typed in unusual Unicode forms differ, and they fail closed (no fill). One host form in App (LD-58). Revisit with (b) if users report it |
| D-INT03-6 | Rank of quoted exact URLs and patterns | (a) exact 100, pattern 40; (b) reference: both 0 | (a). An exact URL is the most specific a user can write; a pattern is the least |
| D-INT03-7 | Order of equal ranks | (a) vault, group tree and stored order; (b) reference: reversed | (a). The order users see in App's own list |
| D-INT03-8 | Hosts without a dot (`nas`, `router`) | (a) rank like any host; (b) reference: rank 0 unless `localhost` | (a). They fit by equality (INT-03.7), so ranking them 0 only pushes the one right entry to the end |

Check with Verify:

| ID | What to check |
|---|---|
| V-INT03-1 | In the reference (a throwaway build of its browser unit tests, or by reading its matcher again): additional URL `https://*.example.com` against page `https://x.example.com.attacker.example/`; `https://*.com/*` against `https://shop.com/`; `https://example.com/*/second` against `https://example.com/a/second/more`. Expected by source reading: all three fit there Confirmed 2026-11-01 by E7-S3 Verify, reading the reference matcher again (LD-330 (3)). |
| V-INT03-2 | In the reference: group option "omit www" with entry `https://www.mywww.example.com` turns the host into `myexample.com` Confirmed 2026-11-01 by E7-S3 Verify, reading the reference matcher again (LD-330 (3)). |
| V-INT03-3 | In the reference: entry `https://b.example.com` fits page `https://ab.example.com/` Confirmed 2026-11-01 by E7-S3 Verify, reading the reference matcher again (LD-330 (3)). |

## Security notes

- **SI-03** (parity row): matching by registrable domain and host suffix (subdomains of the stored host fit), by port when the entry has one, by scheme (S-BRW-11, on); paths only for quoted exact URLs and patterns in additional URLs; local file pages need an exact URL; the reference's lookup scheme by id or path (App: `ids`, INT-01.37). App goes further: effective ports (INT-03.6), whole labels (INT-03.7), anchored patterns with a registrable domain in their fixed part (INT-03.11), a single leading `www` (INT-03.9).
- **AT-F05, lookalike letters and punycode:** hosts are compared in ASCII; a mixed-script name is a different host and never fits; prompts show the ASCII form (LD-58).
- **AT-F05, attacker subdomains:** `example.com.attacker.example` has the registrable domain `attacker.example`; sibling subdomains need whole labels; a public suffix (ICANN or private, such as `github.io`) never acts as one site.
- **AT-F05, http instead of https:** with S-BRW-11 on (default), an `https` entry never fits an `http` page and an entry without a scheme counts as `https`. A user who turns S-BRW-11 off accepts filling `https` entries into `http` pages; Bitwarden warns before filling an `http` site when the saved URI expects `https` (its "URI match detection" help page), which App's extension may also show (E7-S7).
- **AT-F05, other ports:** INT-03.6.
- **IP addresses:** equality only, no subdomain logic and no registrable domain; non-canonical IPv4 forms in entries never fit, so `http://0x7f.1` cannot pose as `127.0.0.1` in a vault. Local network addresses are reused by many networks (a café's router at `192.168.1.1` is not the user's); App cannot tell them apart, which is why HTTP sign-in requests always ask (INT-02.17).
- **Hostile vault data:** a vault can carry URL fields, patterns and allowed hosts that fit any site it names. Patterns can never cover a whole public suffix or reach past the registrable domain of their fixed tail (INT-03.11 steps 1 and 5), all matching is bounded (INT-03.17), and the access rules of INT-02 still apply.
- **What must never happen:** an entry fitting a page outside its registrable domain (patterns included); a match decided by a path for plain URLs; a hang from any URL or pattern; an `https` entry fitting an `http` page while S-BRW-11 is on.

## Test cases

Matcher tests call the matching function directly with an entry and a page; the "find" cases run `logins.find` through INT-01's test client on demo vault V of INT-02 with extra entries as listed. S-BRW-11 on and S-BRW-12 off unless stated. Hosts use reserved demo names (RFC 2606, RFC 6761); `github.io` and `co.uk` appear only as public suffixes from the list. "Fits, n" means fits with rank n; "–" means does not fit.

| Case | Entry URL (main unless "add.") | Page `url` | Then |
|---|---|---|---|
| T01 INT-03.3 | `https://example.com` | `https://example.com/` | Fits, 100 |
| T02 INT-03.3 | `example.com` | `https://example.com/login` | Fits, 85 |
| T03 INT-03.5 | `example.com` | `http://example.com/` | – |
| T04 INT-03.5 | `example.com`, S-BRW-11 off | `http://example.com/` | Fits, 0 |
| T05 INT-03.5 | `http://example.com` | `https://example.com/` | – |
| T06 INT-03.7 | `https://example.com` | `https://mail.example.com/` | Fits, 60 |
| T07 INT-03.7 | `https://example.com` | `https://a.b.example.com/x` | Fits, 60 |
| T08 INT-03.7 | `https://mail.example.com` | `https://example.com/` | – |
| T09 INT-03.7 | `https://b.example.com` | `https://ab.example.com/` | – (reference: fits) |
| T10 INT-03.7 | `https://example.com` | `https://example.com.attacker.example/` | – |
| T11 INT-03.4 | `https://example.com` | `https://xn--exmple-4nf.com/` (Cyrillic `а`) | – |
| T12 INT-03.4 | `https://bücher.example` | `https://xn--bcher-kva.example/` | Fits, 100 |
| T13 INT-03.4 | `https://BÜCHER.example/` | `https://xn--bcher-kva.example/` | Fits, 100 |
| T14 INT-03.4 | `https://EXAMPLE.com` | `https://example.com/` | Fits, 100 |
| T15 INT-03.4 | `https://example.com.` | `https://example.com/` | Fits, 100 |
| T16 INT-03.4 | `https://exa mple.com` | `https://example.com/` | – |
| T17 INT-03.6 | `https://example.com:8443` | `https://example.com:8443/x` | Fits, 85 |
| T18 INT-03.6 | `https://example.com:8443` | `https://example.com/` | – |
| T19 INT-03.6 | `https://example.com` | `https://example.com:8443/` | – (reference: fits) |
| T20 INT-03.6 | `https://example.com:443` | `https://example.com/` | Fits, 100 (reference: –) |
| T21 INT-03.6 | `example.com`, S-BRW-11 off | `http://example.com:8080/` | – |
| T22 INT-03.7 | `http://192.168.1.1` | `http://192.168.1.1/` | Fits, 100 |
| T23 INT-03.7 | `http://192.168.1.1` | `http://192.168.1.10/` | – |
| T24 INT-03.4 | `http://192.168.001.001` | `http://192.168.1.1/` | – |
| T25 INT-03.4 | `http://[0:0:0:0:0:0:0:1]:8080` | `http://[::1]:8080/` | Fits, 100 |
| T26 INT-03.7 | `https://localhost:3000` | `https://localhost:3000/` | Fits, 100 |
| T27 INT-03.7 | `https://nas` | `https://nas/` | Fits, 100 |
| T28 INT-03.7 | `https://nas` | `https://x.nas/` | – |
| T29 INT-03.10 | `https://co.uk` | `https://bank.co.uk/` | – |
| T30 INT-03.10 | `https://name.github.io` | `https://name.github.io/` | Fits, 100 |
| T31 INT-03.10 | `https://name.github.io` | `https://other.github.io/` | – |
| T32 INT-03.10 | `https://github.io` | `https://name.github.io/` | – |
| T33 INT-03.9 | `https://www.example.com`, group omit-www on | `https://example.com/` | Fits, 100 |
| T34 INT-03.9 | `https://www.example.com`, option off | `https://example.com/` | – |
| T35 INT-03.9 | `https://www.mywww.example.com`, option on | `https://mywww.example.com/` | Fits, 100 (reference: host becomes `myexample.com`) |
| T36 INT-03.11 | add. `"https://example.com/login.php"` | `https://example.com/login.php` | Fits, 100 |
| T37 INT-03.11 | add. `"https://example.com/login.php"` | `https://example.com/login.php?x=1` | – |
| T38 INT-03.11 | add. `https://*.example.com` | `https://a.example.com/x` | Fits, 40 |
| T39 INT-03.11 | add. `https://*.example.com` | `https://a.b.example.com/` | Fits, 40 |
| T40 INT-03.11 | add. `https://*.example.com` | `https://example.com/` | – |
| T41 INT-03.11 | add. `https://*.example.com` | `https://x.example.com.attacker.example/` | – (reference: fits, V-INT03-1) |
| T42 INT-03.11 | add. `https://*.com/*` | `https://shop.com/` | – (refused pattern) |
| T43 INT-03.11 | add. `https://*.github.io` | `https://name.github.io/` | – (refused pattern) |
| T44 INT-03.11 | add. `https://example.*` | `https://example.org/` | – (refused pattern) |
| T45 INT-03.11 | add. `https://sub.*.example.com/*/second` | `https://sub.x.example.com/a/second` | Fits, 40 |
| T46 INT-03.11 | add. `https://sub.*.example.com/*/second` | `https://sub.x.example.com/a/second/more` | – (anchored; reference: fits) |
| T47 INT-03.11 | add. `https://example.com/*` | `https://example.com/` and `https://example.com/a/b` | Fits, 40 both |
| T48 INT-03.11 | add. `https://app-*.example.com` | `https://app-eu.example.com/` | Fits, 40 |
| T49 INT-03.11 | add. `https://app-*.example.com` | `https://xapp-eu.example.com/` | – |
| T50 INT-03.11 | add. `https://127.128.*/` | `https://127.128.129.130/` | Fits, 40 |
| T51 INT-03.11 | add. `https://127.128.*/` | `https://127.1.129.130/` | – |
| T52 INT-03.11 | add. `https://127.160.*.2/login` | `https://127.160.8.2/login` | Fits, 40 |
| T53 INT-03.11 | add. `http://[2001:db8::*]/` | `http://[2001:db8::1]/` | – (refused pattern) |
| T54 INT-03.11 | add. `https://example.com:8448/*` | `https://example.com:8449/a` | – |
| T55 INT-03.11 | add. `https://example.com/*/*` | `https://example.com:8449/a/b` | – (reference: fits) |
| T56 INT-03.11 | add. `http*://example.com`, `https://**.example.com`, `https://*.*.example.com` | `https://a.example.com/` | – for each |
| T57 INT-03.3 | main `https://*.example.com` | `https://a.example.com/` | – |
| T58 INT-03.11, INT-03.8 | add. `https://example.com/login` (no `*`) | `https://example.com/other` | Fits, 80 |
| T59 INT-03.2 | main `{REF:A@I:‹id of an entry with URL https://example.com›}` | `https://example.com/` | Fits, 100 |
| T60 INT-03.2 | main `https://{S:host}/`, field `host` = `example.com` | `https://example.com/` | – |
| T61 INT-03.2 | add. `https://{S:host}/`, field `host` = `example.com` | `https://example.com/` | Fits, 100 |
| T62 INT-03.2 | passkey field `KPEX_PASSKEY_RELYING_PARTY` = `example.com` | `https://example.com/login` | Fits, 85 |
| T63 INT-03.3 | `cmd://open https://example.com`; `ftp://example.com` | `https://example.com/` | – both |
| T64 INT-03.3 | `https://example.com/<x>` | `https://example.com/` | – |
| T65 INT-03.3 | `https://user:pw@example.com` | `https://example.com/` | Fits, 100 |
| T66 INT-03.13 | `file:///Users/demo/page.html` | `file:///Users/demo/page.html` | Fits, 100 |
| T67 INT-03.13 | `https://example.com` | `file:///Users/demo/page.html` | – |
| T68 INT-03.12 | main `https://example.com`, Allow `example.org` | `https://example.org/` | Fits, 80 |
| T69 INT-03.12 | same | `http://example.org/`; `https://sub.example.org/`; `https://example.org:8443/` | – each |
| T70 INT-03.12 | main `https://example.com`, Allow and Deny both hold `example.org` | `https://example.org/` | – |
| T71 INT-03.1 | any | `chrome://settings` through `logins.find` | Error 14 |

Ranking and order cases (through `logins.find`):

| Case | Given | When | Then |
|---|---|---|---|
| T72 INT-03.14 | R1 `https://example.com/login`, R2 `https://example.com`, R3 `https://example.com/other`, R4 `https://example.com/login?x=1` | Page `https://example.com/login?x=1` | Order R4 (100), R1 (90), R2 (85), R3 (80) |
| T73 INT-03.15 | Same, S-BRW-12 on | Same | R4 only |
| T74 INT-03.14 | R5 `https://mail.example.com`, R6 `https://example.com` | Page `https://mail.example.com/` | R5 (100), R6 (60) |
| T75 INT-03.14 | R7 `https://example.com/session`, R8 `https://example.com/other` | Page `https://www.example.com/login`, form `https://example.com/session` | R7 (100, equals the form URL), R8 (70) |
| T76 INT-03.16 | Two entries `https://example.com` in groups G1 and G2, G1 first in the tree | Page `https://example.com/` | G1's entry first |
| T77 INT-03.14 | Entry with main `https://example.com/login` and add. `"https://example.com/x"` | Page `https://example.com/x` | Rank 100 (the highest of 80 and 100) |
| T78 INT-03.10 | Hosts `mail.example.com`, `a.b.bank.co.uk`, `user.github.io`, `a.b.example`, `co.uk`, `192.0.2.1`, `localhost` | Registrable domain | `example.com`, `bank.co.uk`, `user.github.io`, `b.example`, none, none, none |

Bounds:

| Case | Given | When | Then |
|---|---|---|---|
| T79 INT-03.17 | Entry URL `https://example.com/` followed by 2,040 `a` (2,060 characters) | Page `https://example.com/` | – |
| T80 INT-03.17 | Entry with 100 additional URLs; only the 80th in INT-03.2's order is `https://example.com` | Page `https://example.com/` | – (only 64 looked at) |
| T81 INT-03.17 | add. `https://example.com/*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*b` (16 `*`) | Page path of 8,000 `a` | –, in under 10 ms |
| T82 INT-03.17 | add. pattern with 17 `*` | Any page | – |
| T83 INT-03.17 | Vault of 10,000 entries with 4 URLs each, release build | `logins.find` on a 8,192-byte page URL | Answer in under 200 ms |
| T84 INT-03.18 | Editor, new website row | Type `https://*.co.uk` | MI03-01 under the row; save still allowed; field name `KP2A_URL` (or the first free `KP2A_URL_n`) |
| T85 INT-03.18 | Editor | Rows `KP2A_URL_10`, `KP2A_URL_2`, `KP2A_URL` | Shown in the order `KP2A_URL`, `KP2A_URL_2`, `KP2A_URL_10` |
| T86 AT-F05 | Entry `https://bank.example.com` (main) | Pages `https://bank.example.com.evil.example/`, `https://xn--bnk-6cd.example.com/` (`bаnk` with Cyrillic `а`), `https://evil-bank.example.com/`, `http://bank.example.com/`, `https://bank.example.com:8443/` | None fits; `logins.find` gives error 15 for each |
| T87 INT-03.3 | `mailto:alex@example.com` (main), and add. `mailto:alex@example.com` | Page `https://example.com/` | – both |
| T88 INT-03.14 | `https://example.com/login`, S-BRW-11 off | Page `http://example.com/login` | Fits, 0 (not 90) |
| T89 INT-03.19 | The test build | Read the build's suffix list: it is a file compiled into the matcher, with its list version recorded in the build; then run T01 to T88 in a test process whose network access is denied (a macOS sandbox profile that denies all network use) | The list is present without any download; every case gives the same result as without the sandbox; the matcher opened no network connection |
| T90 INT-03.19 | `tenant.example` is not on the shipped list (as a suffix added to the list after App's build would not be) | Registrable domains of `a.tenant.example` and `b.tenant.example`; then entry `https://a.tenant.example` against page `https://b.tenant.example/` | `tenant.example` for both (the default rule); – (INT-03.7: whole labels, so one tenant's entry never fits the other tenant's site) |

## How this was learned

- Read in the reference source (development branch): the browser service's URL test (the empty check, quoted exact URLs and wildcards for additional URLs only, the default `https` scheme when the entry has none and scheme matching is on, the leading-`www` option that removes every `www.` text, the file page case that compares with the form URL, the port test only when the entry names a port, the scheme test, the forbidden characters, the wildcard branch before the base domain test, the base domain test and the plain text suffix test), its wildcard matcher (patterns turned into unanchored regular expressions), the rater (the 100, 90, 85, 80, 70, 60, 50 and 0 tiers, the parent-folder test of its URL class, scheme always compared, hosts without a dot rated 0 unless `localhost`), the sorting with its multi-map that returns equal ranks in reverse order, the best-match cut, the search loop that repeats the same search once per dot; the URL tools (base domain and top-level domain through its toolkit's cookie rules, IP detection, the URL validity check used for the editor's colour, which refuses wildcard top-level domains, `**`, `*.*` and empty quotes); the entry's URL helpers (main URL resolved only with a reference, additional URLs by field name prefix plus the passkey relying party field, always resolved); the entry editor's additional URL list and field naming; the browser unit tests for URL matching, wildcards, ports, subdomains, `www`, local files, references and best matches (read for behavior; their URLs are not reused).
- Not run: no browser and no reference build were used; V-INT03-1 to V-INT03-3 record what reading alone could not prove. E7-S3 Verify confirmed all three on 2026-11-01 by reading the reference matcher again (LD-330 (3)).
- Proven standards (AGENTS rule 9), read 2026-10-28: Bitwarden help "URI match detection" (base domain as the default, including subdomains; "Host" includes the port; "Starts with" and "Regular expression" marked as dangerous if used wrongly; a warning before filling an `http` site when the saved URI expects `https`); Bitwarden source `libs/common/src/platform/misc/utils.ts` (registrable domain through `tldts` with private domains allowed, `localhost` and IP addresses compared as whole hosts); crates.io pages of `psl`, `publicsuffix`, `idna` and `url` (versions, licences, update dates). The Public Suffix List site (format, ICANN and private sections, the default rule) and the WHATWG URL Standard (host serialization, IPv4 and IPv6 parsing) are the public standards named above. MOD-08.9 and LD-58, LD-112 and LD-119 give App's own host reading, which this card reuses.

## Review 2026-10-28

Second Spec review. Read again in the reference source: the browser service's URL test, its wildcard matcher, the rater and the sort, the search loop, the URL tools (base domain, top-level domain through the toolkit's cookie rules, IP detection, the editor's validity check) and the entry's URL helpers. Nothing was run; V-INT03-1 to V-INT03-3 stay open for a build-free Verify reading or a test build.

The three reference flaws the first agent found are confirmed by reading:
- **Unanchored wildcards.** The `*` becomes a lazy "any text" group, the pattern is matched without anchors at either end, and the wildcard branch returns before the base domain test. So `https://*.example.com` fits `https://x.example.com.attacker.example/`, `https://*.com/*` fits every host that holds `.com` anywhere (even `x.company.org`), and the path part matches anywhere in the page path (T46). The host rule that should turn a `*` label into whole labels never fires, because the dots are escaped before it looks for them.
- **Subdomains by text.** After the base domains agree, the page host only has to end with the entry host as text: `b.example.com` fits `ab.example.com` (T09).
- **The hang** belongs to INT-02.25 and is confirmed there (an unreadable reference id or a loop of references).
Also confirmed: a public suffix is its own base domain there (`https://github.io` fits its own host), every `www.` text is removed (T35), the port is compared only when the entry names one and against the page's written port (T19, T20), file pages compare with the form URL, the 0 rate for a different scheme and for dotless hosts other than `localhost`, and equal ranks in reverse order. Recomputed and correct: the Punycode forms of T11, T12 and T86.

App's rules checked: wildcards anchored label by label from the right and whole paths; subdomains by whole labels inside one registrable domain; the Public Suffix List with its private section and default rule; IDN through MOD-08.9's encoding with lookalikes failing closed; effective ports on both sides. Every rule has a matcher or `logins.find` test without a browser.

Fixes made (3): INT-03.3 makes a value without `://` that names another scheme (`mailto:`) never fit, where reading it as `https://mailto:…@host` would have fitted the host; INT-03.14 says the 0 rate for a different scheme is checked first (T04 expects it; the table read top-down gave 80); tests T87 and T88.

Findings: none.
