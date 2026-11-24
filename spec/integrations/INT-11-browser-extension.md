# INT-11 Browser extension

Status: reviewed (written 2026-11-01, E7-S7a: Spec reviews 1 to 6, lead rounds LD-295 and LD-298, Verify round 4 signed 2026-11-01; the lead's small follow-ups LD-299)
Epics: E7-S7c (manifest, background, channel, identification key, routing table), E7-S7d (first popup frames), E7-S7e (Safari), E7-S7f (popup and options), E7-S7g (in-page menu, codes, fill), E7-S7h (save, update, new password), E7-S7i (passkeys), E7-S7j (Firefox), E7-S7k (frames for new rows), E7-S7l (the other Chromium browsers), E7-S7m (Red team), E7-S7n (store ids)
Parity rows: SI-01, SI-02, SI-04, SI-10, SI-11, SI-12 (through INT-01 and INT-02); attack rows AT-F01 to AT-F09 (plan/attacks-and-checks.md)

## What it does

Larsal's browser extension is a thin screen and a relay. It finds sign-in fields, asks Larsal over INT-01's channel for matches, entries, codes, passwords and passkeys, draws Option A's 15 extension frames, and fills a page only after the user acts. All the logic that decides (matching, site access, the generator, codes, passkeys) stays in Larsal (INT-01 to INT-04). The extension stores no password and no vault data; it holds a secret only in its background while it draws it, fills it or offers to save it (INT-11.20).

```
web page ── content scripts (classic files, isolated world)  ── in-page frames (extension origin, closed shadow root, top layer)
                 │ runtime messages (sender from MessageSender only)          │
                 ▼                                                            ▼
            background (ES modules: service worker, event page or Safari background) ── popup, options page
                 │ INT-01: connectNative port, or Safari's sendNativeMessage; WebCrypto channel
                 ▼
            larsal-bridge or Larsal's Safari app extension ── Larsal
```

Design and sources: [spec/research/browser-and-web.md](../research/browser-and-web.md) B1 to B12, decided in spec/decisions.md LD-274 (1) and (2); the stack rule of LD-272 (6); the look of Option A's 15 locked extension frames (LD-162, `design/option-a/manifest.json`); the rulings LD-189 and LD-191 (two-step fill, R01-1 `disconnect`, R01-4 no strength or reuse data, R02-4 "Fill when a page loads").

Neighbor cards: INT-01 (the wire, the channel, the error numbers, the store ids), INT-02 (connect, the pairing words, site access, save and update), INT-03 (matching; the extension never matches, and uses INT-03.10's registrable domain only to place a save offer, INT-11.44), INT-04 (passkeys), FEA-02 and FEA-03 (the generator's options and quality words; the word list), APP-01 (S-BRW settings, which live in Larsal, not here).

## Inputs and outputs

### Parts and what each may hold

| Part | Files | Runs as | May hold | Never holds |
|---|---|---|---|---|
| Background | `background.js` and its modules | Chrome, Edge and the other Chromium browsers: MV3 service worker; Firefox: event page; Safari: background script (INT-11.2) | The identification key and the session keys (non-extractable `CryptoKey` objects), the `sid`, the requests in flight, the summaries the popup or a frame shows, one fill's values from the reply until it hands them to one content script, one save or update offer per tab (the typed user name and password) for at most 150 s (INT-11.20), the five options | A master password, a vault key, a vault file, any value after its fill or after the popup that asked for it closed |
| Popup | `popup/` | extension page | The summaries it shows; one entry's fields after Show or Copy; one generated value while shown | Anything after it closes |
| Options page | `options/` | extension page | The status it shows | Any entry data |
| In-page frames | `frames/` (7 pages, INT-11.17) | extension page inside an iframe | Fill menu: the page's summaries; one-time code frame: one code; new-password frame: one generated value; save and update frames: the values the user typed into the page's form | Other entries, keys |
| Content scripts | `content/` (classic files, one fixed order) | isolated world of each http and https frame | The page's fields; the one user name and password (or code) of one fill, until it has filled them | Lists, other entries, keys, the session |
| Page script | `page/passkeys.js` | the page's own world (INT-11.21) | One WebAuthn call in flight | Anything of Larsal's |
| Data files | `words.txt` (INT-11.39), `public_suffix_list.dat` (INT-11.44), `_locales/en/messages.json` (INT-11.22), icons | — | Public data | — |
| Build | `manifest.json.in`, `build.py` (Python 3 standard library) | on this Mac | — | — |

### What the extension stores

| Store | What | Rule |
|---|---|---|
| IndexedDB database `bridge`, object store `keys`, record `identification` | The identification key pair as a `CryptoKeyPair` (private key non-extractable) | INT-11.6 |
| `storage.local` | `options` (the five switches of the options page), `never_save` (hosts, at most 1,000), `last_app_version` (the `app` text of the last hello reply) | INT-11.40, INT-11.20, INT-11.24 |
| anything else (`storage.session`, `storage.sync`, cookies, `localStorage`, files) | nothing | INT-11.15 |

### Limits

| Limit | Value | Rule |
|---|---|---|
| Requests in flight per session | 8 (INT-01.44); further requests wait in the background's queue | INT-11.10 |
| The extension's own wait for a reply to a request that does not wait for the user | 60 seconds (Bitwarden's reply timeout, INT-01 "How this was learned") | INT-11.10 |
| `never_save` | 1,000 hosts, the oldest dropped first | INT-11.20 |
| Search text sent | 256 characters (INT-01.33) | INT-11.29 |
| A fill's values in the background | from the reply until the one `fill` message is sent | INT-11.15 |
| A save or update offer kept for its tab | at most 150 seconds after the submit (Bitwarden's `NOTIFICATION_BAR_LIFESPAN_MS`) | INT-11.20 |

### Minimum browser versions

Each browser's minimum is the lowest release that has every API the code uses (B2). X25519 in WebCrypto decides it everywhere. Sources read 2026-11-01: MDN browser-compat-data (BCD) at commit `0efedff8c8b6f131ad029443056bc74e00b1aca2` (2026-10-31), files `api/SubtleCrypto.json`, `api/HTMLElement.json`, `webextensions/manifest/web_accessible_resources.json`, `webextensions/manifest/browser_specific_settings.json`, `webextensions/api/runtime.json`, `webextensions/api/tabs.json`, `webextensions/api/action.json` and `browsers/*.json` (<https://github.com/mdn/browser-compat-data/tree/0efedff8c8b6f131ad029443056bc74e00b1aca2>); the browsers' own notes linked in the table.

| Browser | Minimum | Written as | What decides it | Source |
|---|---|---|---|---|
| Chrome | 133 | `minimum_chrome_version` `"133"` | X25519 in `generateKey`, `deriveKey`, `importKey`, `exportKey`: 133. Older: `use_dynamic_url` 130, `action.openPopup` 127, the Popover API 114, `MessageSender.documentId` 106, an open native port keeps the worker alive 105 | BCD `api.SubtleCrypto.generateKey.x25519` (and its `deriveKey`, `importKey`, `exportKey` siblings), `webextensions.manifest.web_accessible_resources.use_dynamic_url`, `api.HTMLElement.popover`; Igalia, "Can I use Secure Curves in the Web Platform?" (2025-02-28): "Chrome 133 release shipped with X25519 enabled by default" (<https://blogs.igalia.com/jfernandez/?p=1913>); research section 1 (105). Chrome 133 was released 2025-02-04 (BCD `browsers/chrome.json`) |
| Edge | 133 | `minimum_chrome_version` `"133"` in the Edge build | As Chrome: BCD mirrors Chrome's data for Edge | BCD as above; Edge 133 released 2025-02-06 (`browsers/edge.json`) |
| Firefox | 140 | `browser_specific_settings.gecko.strict_min_version` `"140.0"` | X25519 130, `MessageSender.origin` 126, the Popover API 125; the manifest key `data_collection_permissions`, which Mozilla's add-on site requires of new extensions since 2025-11-03, 140. Newer than the minimum, so used only where present: `MessageSender.documentId` and the `documentId` option of `tabs.sendMessage` 153 (INT-11.12); `action.openPopup` without a user gesture 149 (INT-11.31 calls it from a click) | BCD `api.SubtleCrypto.generateKey.x25519`, `webextensions.api.runtime.MessageSender.origin`, `webextensions.api.runtime.MessageSender.documentId`, `webextensions.api.tabs.sendMessage.options.documentId`, `webextensions.api.action.openPopup` ("Before Firefox 149, a user gesture is required to call this API"), `webextensions.manifest.browser_specific_settings.gecko.data_collection_permissions`; Mozilla Add-ons blog, 2025-10-23 (<https://blog.mozilla.org/addons/2025/10/23/data-collection-consent-changes-for-new-firefox-extensions/>); Igalia: "Firefox 130 shipped both Ed25519 and X25519 enabled by default" |
| Safari | 18.4 | `browser_specific_settings.safari.strict_min_version` `"18.4"`; the extension ships inside Larsal.app, which needs macOS 14 or newer (plan/architecture.md) | X25519 in WebCrypto: 18.4. Older: `MessageSender.documentId` and the `documentId` option of `tabs.sendMessage` 18.4, the Popover API 17, `action.openPopup` 16 | WebKit, "WebKit Features in Safari 18.4" (2025-03-31): "WebKit for Safari 18.4 adds support for X25519 for Web Cryptography" (<https://webkit.org/blog/16574/webkit-features-in-safari-18-4/>); the same page lists macOS Sonoma among its systems. BCD lists Safari 17 for X25519; Igalia's timeline has WebKit turn X25519 on by default in December 2024 and Safari Technology Preview 211 ship it in January 2025, after Safari 17 (2023-09-18), so this card takes Safari's own notes |
| Opera | 118 | the Chrome build's `minimum_chrome_version` (Opera installs it from the Chrome Web Store, B6) | Chromium 133 | BCD `browsers/opera.json`: Opera 118 is Blink 133, released 2025-04-15. Whether Opera applies `minimum_chrome_version` is not documented: check with Verify (E7-S7l); INT-11.5 guards it anyway |
| Brave, Vivaldi, Chromium, Arc | a Chromium 133 base | the Chrome build's `minimum_chrome_version` | Chromium 133 | No compatibility data names these browsers. INT-11.5's start check guards them; E7-S7l runs Brave headless (check with Verify) |

Chrome's own words for the key: it "defines which versions of Chrome are able to install the extension"; the Chrome Web Store shows "Not compatible" to older Chrome, and installed copies stop getting updates (<https://developer.chrome.com/docs/extensions/reference/manifest/minimum-chrome-version>, read 2026-11-01).

## Rules

### Code and builds

INT-11.1 **Plain code** (B1; LD-272 (6)). `extension/` holds ES2022 modules for the background and the extension pages, plain HTML and CSS, and an ordered list of classic files for the content scripts (content scripts cannot import modules in Chromium or Firefox, research section 2). There is no package from a package registry, no bundler, no minifier, no TypeScript compiler, no polyfill and no UI framework; every file ships as written. The code calls `browser.*` after the one line `globalThis.browser ??= chrome` (Chrome's browser-namespace page). No file of a package (INT-11.2) uses `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`, `eval`, `new Function`, a string given to `setTimeout` or `setInterval`, or a remote URL; text goes into the page and the extension pages only with `textContent` (Chrome, "Stay secure"). The extension makes no network request: no file calls `fetch` except on the URL of one of its own files (`fetch(browser.runtime.getURL(…))`, which the data files `words.txt` and `public_suffix_list.dat` need), and none calls `XMLHttpRequest`, `WebSocket`, `EventSource` or `navigator.sendBeacon`. Its only way out is INT-01's channel. The extension registers no `onMessageExternal` and no `onConnectExternal` listener, so other extensions find nobody to talk to.

INT-11.2 **One manifest source, one build per browser** (B2). `build.py` writes each browser's `manifest.json` and package folder from `manifest.json.in`:

| Member | Chrome, Brave, Vivaldi, Opera, Chromium, Arc (one Chrome build) | Edge | Firefox | Safari |
|---|---|---|---|---|
| `manifest_version` | 3 | 3 | 3 | 3 |
| `name`, `version` | `Larsal`, Larsal's version | same | same | same |
| `default_locale` | `en` | `en` | `en` | `en` |
| `background` | both `service_worker` (`background.js`, `type` `module`) and `scripts` (MDN's one-manifest advice); Chrome uses the service worker | same | same; Firefox runs `scripts` as an event page | same; Safari uses `scripts` |
| minimum version | `minimum_chrome_version` `"133"` | `minimum_chrome_version` `"133"` | `browser_specific_settings.gecko`: `id` (Larsal's add-on id, INT-01.9), `strict_min_version` `"140.0"`, `data_collection_permissions` `{"required":["none"]}` | `browser_specific_settings.safari.strict_min_version` `"18.4"` |
| `key` | development builds only, so the unpacked id stays fixed for `allowed_origins` (Chrome, "Manifest key") | development builds only | — | — |
| `permissions` | INT-11.3 | INT-11.3 | INT-11.3 | INT-11.3 |
| `content_security_policy` | `{"extension_pages":"script-src 'self'; object-src 'self'"}` | same | same | same |
| `content_scripts` | INT-11.16 | same | same | same |
| `web_accessible_resources` | INT-11.17 and INT-11.21, with `use_dynamic_url` `true` | same | same (Firefox has no `use_dynamic_url`; its extension URL holds a UUID "randomly generated for every browser instance", MDN) | same (Safari's base URL "is always dynamic", BCD) |
| `action` | `default_popup` `popup/popup.html` | same | same | same |
| `options_ui` | `{"page":"options/options.html","open_in_tab":true}` | same | same | same |
| `commands` | INT-11.41 | same | same | same |

The CSP is Chrome's MV3 default for extension pages, `script-src 'self'; object-src 'self';`, written out so every browser applies the same one; it allows no WebAssembly and no `'unsafe-eval'` (Chrome, "Manifest content_security_policy"; B3 needs no WebAssembly). Each package holds only the files it uses and no generated or minified file, so Mozilla's add-on site needs no source upload (research section 4).

INT-11.3 **Permissions** (B2). Exactly: `nativeMessaging`, `storage`, `activeTab`, `scripting`, and the host permissions `http://*/*` and `https://*/*` (the in-page frames need them on every site). No other permission, no `optional_permissions`, no `externally_connectable`. Safari requires `nativeMessaging` for its native messages (Apple). `scripting` puts the content scripts into tabs that were already open when the extension started (the manifest's content scripts reach only pages loaded later). When the user takes the host permissions back (Firefox allows it at any time, research section 4), content scripts stop: opening the popup on a tab gives the extension that tab through `activeTab` (the user invoked it, Chrome and MDN), the background puts the content scripts into it with `scripting.executeScript`, and the popup's fills work on that tab; no in-page menu shows; the popup shows MI11-62 (INT-11.23).

INT-11.4 **Store ids** (B6; INT-01.9). One Chrome Web Store listing serves Chrome, Brave, Vivaldi, Opera and Arc; Edge Add-ons gives a second id; Firefox gets one gecko id; Safari ships inside Larsal.app. The ids are fixed at the first publish (E7-S7n, owner steps, LD-272 (4)); until then development builds use the `key` member's id, and Larsal's debug builds list it (INT-01.9).

INT-11.5 **Start check.** At each start the background makes one throwaway X25519 key pair with `crypto.subtle.generateKey({name:"X25519"}, false, ["deriveKey"])`. When the call rejects (the browser lacks X25519), the background opens no port, sends nothing, and the popup shows MI11-60 with the minimum of the table above for this browser. This guards the browsers whose minimum no manifest key can enforce (Opera, Brave, Vivaldi, Chromium, Arc).

### The identification key and the channel

INT-11.6 **The identification key** (B3; INT-01.28). One per browser profile. Made the first time a hello succeeds and no record exists: `crypto.subtle.generateKey({name:"X25519"}, false, ["deriveKey"])`, so the private key's `extractable` is false; the public key is always extractable (W3C WebCrypto, X25519 "Generate Key"). The `CryptoKeyPair` is stored as one record in IndexedDB (database `bridge`, store `keys`, key `identification`): `CryptoKey` objects are serializable, so IndexedDB keeps them without their bytes ever reaching script (W3C WebCrypto: "CryptoKey objects are serializable objects"; "most authors will make use of the Indexed Database API"). `exportKey` on the private key fails; only the public half is exported, as `raw` (32 bytes), for `id_key`. The key never goes into `storage.local`, a message to a content script or frame, a log or the page. When the record is gone (profile reset, extension removed, site data cleared), a new key is made: Larsal no longer finds it (`check`: error 8) and the popup starts the first connection (INT-11.25). On `disconnect`'s reply, or on its error 8 (no vault the request may use holds this key, INT-01.30), the record is deleted at once; on any other error it stays (INT-11.40).

INT-11.7 **The channel in WebCrypto** (B3; INT-01.20, INT-01.21, INT-01.23, INT-01.28, INT-01.49). For each hello the background:
1. makes a session key pair: `generateKey({name:"X25519"}, false, ["deriveKey"])`; exports the public key `raw` as C and sends the hello (INT-01.20);
2. imports Larsal's key A from the reply with `importKey("raw", A, {name:"X25519"}, true, [])` (raw is the public-key format, 32 bytes, W3C WebCrypto X25519 "Import Key");
3. derives the HKDF key straight from X25519: `deriveKey({name:"X25519", public: A}, c, "HKDF", false, ["deriveKey"])`, so the X25519 secret never becomes a JavaScript value (BCD `api.SubtleCrypto.deriveKey.derivedKeyAlgorithm_option_hkdf`: Chrome 41, Firefox 119, Safari 11); WebCrypto throws `OperationError` when the X25519 result is all zero (W3C WebCrypto X25519 "Derive Bits", after RFC 7748 section 6.1): the background then drops the session and says hello again once, then reports Larsal as not reachable;
4. derives the request key and the reply key with `deriveKey({name:"HKDF", hash:"SHA-256", salt: empty, info}, hkdfKey, {name:"AES-GCM", length:256}, false, [usage])`, with INT-01.49's info bytes; the request key gets only `encrypt`, the reply key only `decrypt`;
5. seals each request with `encrypt({name:"AES-GCM", iv: nonce}, requestKey, content)` (tag 128 bits, no `additionalData`), with a fresh nonce from `crypto.getRandomValues(new Uint8Array(12))`, and opens each reply and notice with the reply key.
For a proof (INT-01.28) it derives the proof key from the identification private key and A the same way (steps 3 and 4, with the proof key's info and usage `encrypt`) and seals C under it with that request's nonce. Every key above is non-extractable; the session's keys are dropped (references cleared) when the session ends. The extension ships no JavaScript crypto code (LD-274 (1)).

INT-11.8 **The port** (B4; Chrome-family and Firefox). The background keeps one `runtime.connectNative("app.larsal.browser")` port; an open port keeps Chrome's worker alive (Chrome 105 and later, research section 1). On connect it says hello. On `onDisconnect` it connects again at once and says hello; when that port also closes within 1 second, it stops trying until the next need (the popup or options page opens, a content script reports fields, Try Again, a keyboard command), so a missing host never makes a loop. While the host program answers 44 or 45 (INT-01.5) the port stays open; the background sends a new hello at each need and every 1 second while a popup or the options page is open (INT-01.5's own retry pace), so Larsal started later is reached without a reload. Requests in flight when the port closes fail as not reachable; nothing is resent on its own except INT-11.10's one retry.

INT-11.9 **The Safari route** (INT-01.13, INT-01.14). Safari has no host program: the background sends each message with `browser.runtime.sendNativeMessage` (Safari routes it to Larsal's app extension whatever id it names, Apple) and takes the one reply as that message's answer. The session is found by `sid`; Larsal sends no notices here (INT-01.46), so the state comes only from the `status` and `check` the background sends each time the popup or the options page opens (INT-11.10). A Safari session ends after 15 minutes without a request (INT-01.14): the next request gets plain error 3 and INT-11.10's retry says hello again.

INT-11.10 **Requests and replies.** Each request gets the next `req` (1, 2, …, per session) and a fresh nonce; the background keeps `req` → (nonce, caller) until its reply. A reply is taken only when it opens with the reply key, its `req` is waiting and its nonce equals that request's nonce (INT-01.23). A boxed message without `req` that opens with the reply key and holds `"type":"notice"` is a notice (INT-01.46): the popup and the options page read the state again (INT-11.23), and nothing else is done. Anything else is dropped without effect. A new hello ends the session before it in the background, on both routes: each request still waiting under the old session is dropped from the `req` table at once and its caller is told that the session ended. The popup and the options page then read the state again (below), an in-page frame closes and fills nothing, and a waiting `connect` no longer waits (INT-11.25). A reply that comes later for the old session finds no waiting `req` and is dropped. Only the request that got plain error 3 or 41 is sent again (below). At most 8 requests are in flight (INT-01.44); more wait in the background's queue. A request that does not wait for the user (`status`, `check`, `logins.find`, `logins.search`, `logins.recent`, `groups.list`, `password.generate`, `lock`, `code.get` of an allowed entry) fails as not reachable after 60 seconds; requests that wait for the user have no own limit (INT-01.45 bounds them). Plain errors 3 and 41 (session gone or used up): the background says hello again, proves its identity with `check`, and sends the request once more; a second failure reports Larsal as not reachable. Plain error 4: a new hello, no retry. Plain 44 or 45: Larsal is not reachable (INT-11.24). Boxed errors go to the caller, which shows INT-11.22's text for the number. The state the popup and the options page show (INT-11.23) comes from one `status` and one `check` (with `id_key` and `proof`, INT-01.28), which the background sends after each hello, each time the popup or the options page opens, and on each notice. It never reuses an older reply, so a `check` error 8 from before an unlock never decides a frame.

### Senders, fills and secrets

INT-11.11 **Sender checks** (B9). The background trusts no message from a content script (Chrome, "Stay secure"). For every runtime message it takes the frame's `url`, `origin`, `frameId`, `documentId` (where the browser has it, BCD: Chrome 106, Safari 18.4, Firefox 153) and the tab from `runtime.MessageSender`, which a compromised renderer cannot spoof in Chromium (Chromium, "Threat Model And Defenses Against Compromised Renderers"); a URL or origin written in the message body is ignored. A message is refused (no reply, nothing done) when: `sender.id` is not this extension's id; the sender's `origin` is opaque (`null`) or differs from the origin of its `url`; the `url` is not `http:` or `https:` (content scripts) or not this extension's own origin (extension pages); or the route of INT-11.12 does not allow that kind of sender. `top_url` (INT-01.27) is the sender tab's `url`; `form_url` is the only page-made value the background passes on (the form's `action` as the content script reads it); it can only make INT-02.19 ask, never skip a question.

INT-11.12 **The routing table.** One table in `background.js` names each internal route, who may send it and what the background does; anything not in it is refused. Senders are classed by `sender.url` (INT-11.11), not by `sender.tab`: Chrome fills `sender.tab` for every sender in a tab ("present when the connection was opened from a tab (including content scripts)", Chrome, `runtime` API, `MessageSender`), and the options page runs in a tab (INT-11.2's `open_in_tab`).
- **C** a content script: `sender.url` is `http:` or `https:`, and `sender.tab` is set.
- **F** an in-page frame: `sender.url` is this extension's URL under `frames/`, `sender.tab` is set, and `frameId` is not 0 (Chrome: `frameId` "will only be set when tab is set", and 0 is the top frame), so a frame page that a site loads as a whole tab is refused.
- **P** the popup or the options page: `sender.url` is exactly this extension's `popup/popup.html` (no `sender.tab`) or `options/options.html` (`sender.tab` allowed, `frameId` 0).
- Any other sender is refused.

Whether Chrome reports a frame page loaded from its dynamic URL (INT-11.17) with that dynamic origin is not documented (Chrome, "Manifest web_accessible_resources"): check with Verify in E7-S7c (T77) before the extension-origin test of INT-11.11 is coded.

| Route | Sender | What the background does |
|---|---|---|
| `fields.found` | C | Notes which kinds of field the frame has (sign-in, new password, one-time code); calls `logins.find` for the top frame to set the badge (INT-11.42); answers nothing secret |
| `menu.open` | C | Only after a trusted click in a detected field or on Larsal's mark (INT-11.13): issues a one-time menu token for (tab, frameId, documentId where the browser has it, origin) and the frame to show (INT-11.19) |
| `frame.ready` | F | With a live token of the same tab that no frame has said `frame.ready` with yet (INT-11.19): ties the token to this frame and sends it what it draws (summaries, a code, a generated value, the save or update card's data) |
| `frame.pick`, `frame.use`, `frame.save`, `frame.update`, `frame.passkey` | F | With a live token, from the frame it is tied to: asks the host content script for INT-11.18's checks; only when they pass does it act (INT-11.13, INT-11.20, INT-11.21) |
| `frame.popup` | F | With a live token, from the frame it is tied to: notes the view (`search` or `generator`) the next popup opens on (INT-11.31) |
| `frame.close` | F, C | Drops the token |
| `form.submitted` | C | INT-11.20 |
| `passkey.request` | C | INT-11.21 |
| `popup.*` (`status`, `matches`, `search`, `recent`, `get`, `code`, `generate`, `fill`, `lock`, `unlock`, `connect`, `cancel`) | P | The popup's requests (INT-11.23 to INT-11.33) |
| `options.*` (`status`, `disconnect`, `set`) | P | INT-11.40 |

Messages from the background to content scripts (`menu.check`, `fill`, `fill.code`, `frame.show`, `frame.hide`) are sent with `tabs.sendMessage(tabId, message, options)` to the one frame of the token. `options` holds `frameId`, and `documentId` only where the browser has it: when the token's sender came with a `MessageSender.documentId` (BCD gives both in the same releases: Chrome 106, Safari 18.4, Firefox 153; `webextensions.api.tabs.sendMessage.options.documentId`, `webextensions.api.runtime.MessageSender.documentId`). Where it has not (Firefox 140 to 152), `frameId` and INT-11.15's origin check guard the fill. Content scripts take messages only from the background (`sender.id` is the extension and `sender.tab` is absent).

INT-11.13 **Fill only on a user action** (B9; Princeton CITP; Oesch and Ruoti section 7.1). A fill happens only after one of: a pick in Larsal's in-page fill menu (after INT-11.18's checks), Fill (or Fill sign-in, Fill code, Fill on page) in the popup, or the keyboard command "Fill the best match" (INT-11.41). A page event, a focus, a page load (except INT-11.14) or a message from a page never fills. The in-page menu opens only on a trusted (`isTrusted`) click in a detected field or on Larsal's mark in it, or on the keyboard command; a focus alone does not open it. A fill goes into the frame the user acted on: for the menu, the token's frame; for the popup and the command, the frame of the active tab whose document last had focus in a detected field, else the top frame's first sign-in form, else nothing. A fill into an iframe needs an explicit pick, and Larsal's INT-02.19 prompt decides for frames of other sites. The extension never presses a page's button and never submits a form, so `skip_submit` (INT-02.20) changes nothing it does; the popup says so (MI11-17).

INT-11.14 **Fill when a page loads** (B9; LD-191 (R02-4)). Off by default ("Off is safer"). When the user turns it on, the background fills on a page load only when all hold: the frame is the top frame (`frameId` 0); its URL is `https:`; `logins.find` gives exactly one entry and its `access` is `allowed` (INT-02.20); the page has one visible sign-in form. Then it sends `logins.get` for that one entry, once per document. It never fills an iframe this way, never fills when Larsal would ask (an entry in state `ask`), and so never makes Larsal open a dialog on a page load.

INT-11.15 **Where secrets go.** A password, user name or code from `logins.get` or `code.get` stays in the background only until it sends the one `fill` message to the one frame the user acted on; it is not cached, not written to any store, and not sent to any frame page. The content script checks before filling that its own `location.origin` equals the origin the background sent with the fill (a frame that navigated meanwhile fills nothing), fills, fires the `input` and `change` events the page listens to, and drops the values. The popup drops every secret when it closes; the background keeps nothing for it. Copy in the popup writes with `navigator.clipboard.writeText` inside the click when the value is already held; when it first has to ask Larsal, the button turns to MI11-18 and the next click writes it. The extension cannot clear the clipboard later (it holds no clipboard-read permission): a known limit (Security notes). Nothing the extension holds is written to a log or the console.

INT-11.16 **Content scripts** (B1; research section 2). The manifest's `content_scripts`: `matches` `http://*/*` and `https://*/*`, `all_frames` true, `run_at` `document_start`, `js` the classic files in one fixed order, no `world` member (isolated world), no `match_about_blank` and no `match_origin_as_fallback`, so they never run in `about:`, `data:` or `blob:` frames, and such frames are never filled. In a sandboxed `http` or `https` frame they may run (the URL matches), but its origin is opaque (`origin` can "be opaque (e.g., sandboxed iframes)", MDN, `runtime.MessageSender`; research section 2), so INT-11.11 refuses every message it sends and it is never filled. They find fields: a password field is an `input` of type `password`; its user name field is the nearest text or email `input` before it in the same form (or the same shadow root), preferring `autocomplete` `username` or `email`; a new-password field has `autocomplete` `new-password`, or is one of two or more password fields of one form; a one-time code field has `autocomplete` `one-time-code` (WHATWG HTML, autofill tokens). Hidden fields (zero size, `display:none`, `visibility:hidden`, `opacity` 0, off screen) are not offered and never filled (Princeton CITP: invisible forms). These rules are a pure module tested under macOS's `jsc` (B11).

### In-page frames

INT-11.17 **The in-page frames** (B10). Each of the 7 in-page frames (`extension-in-page-fill-menu`, `-one-time-code`, `-new-password`, `-save-sign-in`, `-update-password`, `-save-passkey`, `-sign-in-with-passkey`) is a page under `frames/`, listed in `web_accessible_resources` for `http://*/*` and `https://*/*` with `use_dynamic_url` true (its URL changes at each browser restart or extension reload, Chrome). The content script shows it in an `iframe` inside a closed shadow root on a host element it appends as the last child of the document element; the host carries `popover="manual"` and is shown with `showPopover()`, so it sits in the top layer; the host's inline style sets `opacity: 1`, `visibility: visible`, `pointer-events: auto`, `filter: none` and its position with `!important`. The page can see the host element but nothing inside it. Lists, titles and user names are drawn only inside the frame page, where the page cannot read them (D-INT01-9).

INT-11.18 **Checks before a click counts** (B10; Toth, "DOM-based Extension Clickjacking"). A click or key press in an in-page frame counts only when it is trusted (`isTrusted`) and, at that moment, the host content script finds all of these true (the two items that only open the toolbar popup need only `isTrusted`, INT-11.31):
1. `getComputedStyle` gives `opacity` exactly 1, `visibility` `visible`, `display` not `none`, `filter` `none` and `mix-blend-mode` `normal` for the document element, `body`, the host and each ancestor of the host;
2. no `style` or `class` change on any of those, no change of the host's attributes, and no node added after the host happened since the frame was shown (a MutationObserver watches them from the moment it shows);
3. no other top-layer element is open: no element of the document or of its open shadow roots matches `:popover-open`, `:modal` or `:fullscreen` but the host;
4. `document.elementsFromPoint` at the click point (the frame's point plus the iframe's position) gives the host first;
5. the host is still the document element's last child and still shown as a popover.
On any doubt the content script closes the frame, nothing is filled or sent, and the background sets the tab's badge to `!` and shows MI11-63 the next time the popup opens: the toolbar popup is the safe way, because the page cannot cover it. Toth writes that no single defence is enough ("Doesn't exist simple protection") and that `elementsFromPoint` does not see `pointer-events: none` popovers, so all five run. A page's popovers inside its own closed shadow roots cannot be seen: a known limit (Security notes).

INT-11.19 **The menu token.** The background ties each shown in-page frame to one frame of one page with a token of 16 random bytes (`getRandomValues`; 128 bits, the size of INT-01.20's `sid`), given to the content script and put in the iframe's URL fragment. The frame page sends it with `frame.ready`; the background takes the frame's requests only while the token is live and the frame's `sender.tab` is the token's tab. The first `frame.ready` with a token ties the token to that sender's `frameId` (and `documentId` where the browser has it, INT-11.12); from then on the background takes frame routes with that token only from that frame. A second `frame.ready` with the token, or any frame route with it from another frame, is refused and ends the token: the background sends `frame.hide`, and nothing either frame sent after that counts. A token ends when its frame closes, the page's document changes, the tab closes, a pick is done, its save or update offer is dropped (INT-11.20), or after 10 minutes (Larsal's own bound: a frame serves one sign-in, which takes far less, and the bound ends a token whose close was missed). So a page that learns a token gains little: its own scripts cannot send `frame.*` routes (INT-11.12), and a copy of a frame page it loads with the token in the same tab is refused when Larsal's own frame said `frame.ready` first, and ends the token the moment Larsal's own frame says it when the copy was first. A known limit: in the few milliseconds before Larsal's own frame loads, a pick in a copy that was first could still count; it needs a token, which exists only in the background, the content script and the closed shadow root (Security notes).

INT-11.20 **Save and update offers** (INT-02.24, INT-02.25; LD-191 (R01-4)). When a form with a filled password field is submitted (the content script sees the `submit` event, or a click on its submit button followed by the page's navigation), the content script sends `form.submitted` with the form's user name and password values. The background then, using the page's last `logins.find` summaries:
- with "Offer to save new sign-ins" on, the page's host not in `never_save`, and no summary with that user name: shows `extension-in-page-save-sign-in` (INT-11.36);
- with "Offer to update changed passwords" on, a new-password field in the form, and a summary with that user name (or exactly one summary when the form has no user name field): shows `extension-in-page-update-password` (INT-11.37);
- else nothing; a sign-in with a known user name never asks.

When the password came from Larsal's generator through Use or Fill on page (INT-11.34, INT-11.30), the next submit of that form:
- with no summary that has the form's user name (and, when the form has no user name field, not exactly one summary): saves at once with `logins.save` and no card, as the new-password frame says (MI11-46);
- else (a summary with that user name, or exactly one summary when the form has no user name field): shows `extension-in-page-update-password` (INT-11.37) for that summary whatever "Offer to update changed passwords" says, because Use was the user's own action (as the save branch above ignores "Offer to save new sign-ins"); so a change-password form updates the entry it belongs to, never adds a second one with the new password, and never loses the new value the site now holds (MI11-46 b).

"Never for this site" adds the form page's host (the host of the offer's `url`, below) to `never_save` (never the host of the document the frame shows in); `never_save` keeps at most 1,000 hosts and drops the oldest first (Larsal's own bound, so the list cannot grow without end: 1,000 host names of at most 255 octets each, RFC 1035 section 2.3.4, take about 0.26 MB of `storage.local`'s 10 MB, Chrome, `storage` API, `QUOTA_BYTES`).

An offer belongs to its tab, because most forms load a new page on submit: one offer per tab, shown only in a document of the offer's site, for at most 150 s after the submit (LD-295 (1); source note below). The background keeps the offer in memory only: the user name, the password, the form page's `url` (the frame the form was in, INT-11.11), the form's `form_url`, the user name of the form page's first match (INT-03.14's order) when it had matches, and the summary to update.
- A frame of a kept offer takes everything from the offer, never from the document it shows in: ‹host› in INT-11.36's Title row and in MI11-56 is the form page's host; MI11-56, with that user name as ‹username›, shows when the offer holds one; `logins.save` and `logins.update` send the offer's `url` and `form_url`; Never for this site adds the form page's host.
- It shows the offer's frame in the form's document while that document lives. Then it shows it again each time the tab's top frame shows a document on the offer's site while no frame of the offer is open: at each new document (`tabs.onUpdated` with `status` `complete`) and when the tab becomes active again (`tabs.onActivated`). The host permissions let the background read the tab's `url` ("Host permissions allow an extension to read and query a matching tab's four sensitive `tabs.Tab` properties", Chrome, `tabs` API), so no new permission is needed (INT-11.3).
- The offer's site is the registrable domain of the page the form was in (INT-11.44), or its host when it has none; a top-frame document whose registrable domain (or host) differs is of another site.
- Each showing gets a new token for the tab's top frame (INT-11.19) and a `frame.show` that carries the origin the background read; the content script shows nothing unless its own `location.origin` equals it (as INT-11.15 checks a fill).
- The offer and its values are dropped on Larsal's reply to Save's `logins.save` or Update's `logins.update` (a result; for `logins.update` also error 6), Not Now, Never for this site, Close or Escape in its frame; a new offer in the same tab; the tab closing (`tabs.onRemoved`); the tab's top frame showing a document of another site; or 150 s after the submit; whichever comes first. While an offer's `logins.save` or `logins.update` waits for its reply, the background sends no other request for that offer: Save and Update in any frame of the offer do nothing until the reply. Dropping an offer for any reason sends `frame.hide` to its open frame and ends its token (INT-11.19), so no frame holds the values after that. On any other error of `logins.save` or `logins.update` the frame stays open and shows INT-11.22's words in one line (INT-11.33). The offer stays, so Save or Update can be clicked again until another drop reason or the 150 s. A click outside the frame, the document changing and the tab going to the background close only the frame (INT-11.35).

Source note (LD-294 (3)): this is the practice of Bitwarden's open source browser extension, which keeps one offer per tab, shows it only on a tab whose registrable domain equals the offer's, and keeps it 150 s (`NOTIFICATION_BAR_LIFESPAN_MS = 150000; // 150 seconds`; github.com/bitwarden/clients, `apps/browser/src/autofill/background/notification.background.ts` and `libs/common/src/autofill/constants/index.ts`, read 2026-11-01).

No strength, reuse or match data for a typed password is asked for or shown (LD-191 (R01-4)).

INT-11.21 **Passkeys** (INT-04; E7-S7i). With "Use Larsal for passkeys" on, the content script adds, at `document_start`, one `script` element whose `src` is `page/passkeys.js` from `web_accessible_resources` (a dynamic URL), then removes the element; the page script wraps `navigator.credentials.create` and `get` in the page's world and passes the options to the content script by `window.postMessage`. That message is page data: the background sends `passkey.create` or `passkey.get` with `origin` taken only from `MessageSender` (B9), never from the message. The two passkey frames (INT-11.38) show before Larsal is asked. "Use another device", Cancel, Larsal's refusal, Larsal not reachable, or a page CSP that blocks the page script: the browser's own WebAuthn flow runs unchanged (the original functions are called). The flow inside Larsal (who confirms, the countdown) follows INT-04 as the lead rules finding R04-1 (LD-215); this card fixes only the extension's side.

### Words and frames

INT-11.22 **Words.** Every string the extension shows is a message of `_locales/en/messages.json`, read with `browser.i18n.getMessage`, and every accessible name is one too; its name is the message id with `_` for `-` and for the space (`MI11_01`, `MI11_04_b`), because a name may hold only `A-Z`, `a-z`, `0-9`, `_` and `@` (Chrome, "Localization message formats"). Each text in the Messages table has its own id: a row's "b" text is the id with ` b`, and the groups MI11-98, MI11-100, MI11-101 and MI11-102 give one letter to each text. Placeholders `‹…›` are message substitutions. `getMessage` only puts strings into a message (Chrome, `i18n` API: "Up to 9 substitution strings"), so it has no plural forms: where a count is 1, the row's "b, for one" text shows (MI11-21, MI11-41, MI11-48). Vault data (titles, user names, hosts, codes, vault and group names), the key marks `⏎`, `⌥⇧A`, `⌥⇧F` and `⌥⇧G`, the badge's count and `!`, and the joins ` · ` and `‹host› (‹username›)` are not words, so they have no message. Larsal 1.0 ships English only. Error numbers from Larsal (INT-01.40) map to these words, and no error text from Larsal exists to show:

| Error | Shown |
|---|---|
| 1 | the locked frame (INT-11.26), or MI11-64 when no vault is open; for the options page's `disconnect`, MI11-104, or MI11-64 when no vault is open (INT-11.40); in an in-page frame, MI11-105, or MI11-64 when no vault is open (INT-11.33) |
| 6 | MI11-65 |
| 8 | the first connection (INT-11.25); for the options page's `disconnect`, no words: the key is deleted (INT-11.40); in an in-page frame, MI11-99 in one line (INT-11.33) |
| 15 | MI11-66 |
| 18 | MI11-67 |
| 34 | MI11-68 |
| 42 | MI11-69 |
| 43 | MI11-70 |
| 10, 12, 13, 14, 16, 17, 20 to 33 (passkey results go to INT-04's flow), any other | MI11-71 |
| 3, 4, 41 | INT-11.10 (a new hello) |
| 44, 45, a missing host | the not-reachable frame (INT-11.24); in an in-page frame, MI11-01 in one line (INT-11.33) |

INT-11.23 **Which popup frame shows.** When the popup opens it asks the background for the state and shows, first match wins:

| State | Frame |
|---|---|
| INT-11.5's check failed | `extension-popup-app-not-reachable` with MI11-60 |
| no port, or 44, 45 | `extension-popup-app-not-reachable` (INT-11.24) |
| `status`: the shown vault is locked | `extension-popup-vault-locked` (INT-11.26) |
| `status` lists no vault | MI11-64 in one line (INT-11.33) with Open Larsal (MI11-10, D-INT11-1); no `connect` is sent (a new state, D-INT11-2) |
| `check` gave error 8 | `extension-popup-first-connection` (INT-11.25) |
| the user picked an entry | `extension-popup-entry` (INT-11.28) |
| the search field holds text | `extension-popup-search-everything` (INT-11.29) |
| the Generator tab | `extension-popup-generator` (INT-11.30) |
| otherwise | `extension-popup-matches-for-this-site` (INT-11.27) |

The host permissions taken back (Firefox, INT-11.3): MI11-62 above the matches frame; fills reach only the tab the popup was opened on. A safety close (INT-11.18): MI11-63 above whichever frame shows. The `status` and `check` replies are fresh: the background sends both each time the popup opens and on each notice (INT-11.10). The locked row comes before the error 8 row because `check` lists only unlocked vaults (INT-02.7: "None: error 8"), so a locked vault gives 8 for a paired browser too; that browser shows the locked frame and sends no `connect`, and after the unlock the new `check` passes. The no-vault row comes before the error 8 row too: with no vault open `check` gives 8 (INT-02.7) and a `connect` would get error 1 at once (INT-02.3), so the frame would show pairing words that no Larsal dialog follows.

INT-11.24 **Frame `extension-popup-app-not-reachable`.** Title MI11-01, text MI11-02, then three checks, each with a mark (done, failed, unknown) and a hint line:

| Check | Done | Failed | Unknown |
|---|---|---|---|
| MI11-03 Larsal is installed | the host program answered (44 or 45), or Safari's handler answered | `connectNative` found no host (Larsal is not installed, or this browser is off in Larsal's settings) | — |
| MI11-05 Larsal is running | the host program answered 45 | it answered 44 | no host |
| MI11-07 Browser Integration is on for ‹browser› | — | it answered 45 | 44 or no host |

Hint lines: MI11-04 under the first (with `last_app_version` when a hello was ever answered, else MI11-04 b), MI11-06 under the second, MI11-08 under the third. Buttons: Try Again (MI11-09: a new hello now) and Open Larsal (MI11-10, D-INT11-1). With Larsal reachable again the popup changes to the right frame without a reload (INT-11.8).

INT-11.25 **Frame `extension-popup-first-connection`** (INT-02.3 to INT-02.6). When this frame shows (`check` gives error 8, and `status` lists a shown vault that is not locked, INT-11.23), the popup sends `connect` (with `id_key`, `proof`; `name` left out, so Larsal suggests "‹browser› on ‹computer name›", INT-02.4). Title MI11-11 with the browser's name, text MI11-12, the four pairing words of INT-11.39, MI11-13 while Larsal's dialog is open, and Cancel (MI11-14). Cancel closes the popup, because no other popup frame can show while `check` still gives 8 (INT-11.23). On the port route (INT-11.8) it first says hello again on the same port, which replaces the session and closes Larsal's dialog as Deny (INT-01.20). On the Safari route a new hello does not end Larsal's waiting session, because Larsal finds Safari sessions by `sid`, not by the connection (INT-01.14): there Cancel only closes the popup, Larsal's dialog stays until the user answers it in Larsal or it closes after 120 s (INT-01.45), and the background takes the `connect` reply as usual. Results: a name and vault id → the matches frame; error 1 (the vault is locked) → the locked frame, then `connect` again after the unlock; error 6 → MI11-61 with Try Again. The popup closing does not cancel: Larsal's dialog stays until the user answers it or its own timeout (120 s, INT-01.45). While a `connect` waits (until its reply comes, or a new hello ends its session, INT-11.10), a new popup shows this frame and sends no second `connect`, so Larsal never queues a second dialog for this browser (INT-01.44, INT-02.15). A `connect` result that comes while no popup is open is kept in the background until the next popup opens: error 6 then shows MI11-61 with Try Again, in place of a new `connect`; error 1 shows the locked frame as above; a name and vault id needs nothing kept, because `check` then passes.

INT-11.26 **Frame `extension-popup-vault-locked`** (B8). Title MI11-15 with the shown vault's name from `status`, text MI11-16, button "Unlock in Larsal" (MI11-19), which sends `unlock` and nothing else; the extension never asks for or sees a master password. The line "Other vaults: ‹names›" (MI11-20) lists the other open vaults and their states from `status`; it has no action (D-INT11-3). `unlock`'s reply → the background sends `status` and `check` again and the popup shows INT-11.23's frame: the matches frame when `check` passes, the first connection when it gives 8; error 1 (S-BRW-10 off: Larsal answers at once and opens no unlock panel, INT-02.11) → the locked frame stays and shows MI11-103 in one line (INT-11.33). The vault is open, only locked, so MI11-64 never shows here.

INT-11.27 **Frame `extension-popup-matches-for-this-site`.** Header: the vault name and MI11-21 (host and match count), Open Larsal (MI11-10), Lock ‹vault› (MI11-22: sends `lock`). Search field (placeholder MI11-23). Section MI11-24 with the active tab's matches from `logins.find` (summaries, INT-02.20), each with Fill (MI11-25) and Copy password (MI11-26); a row's title opens the entry frame. Section MI11-27 for each match whose `code` is true and whose `access` is `allowed`, with its code from `code.get` (renewed when `remaining` reaches 0), Fill code (MI11-28) and Copy code (MI11-29). Section MI11-30 with `logins.recent` (Copy password only). Tabs: MI11-31 Entries, MI11-32 Codes (the code rows only), MI11-33 Generator, MI11-34 Settings (opens the options page). No matches: MI11-72 in place of the section.

INT-11.28 **Frame `extension-popup-entry`.** Back (MI11-35), the title and host, Open in Larsal (MI11-36, D-INT11-1). Fields from `logins.get` for that one entry, asked when the frame opens (Larsal asks first when the entry is in state ask): Username with Copy username (MI11-37), Password masked with Show password (MI11-38) and Copy password, One-time code with MI11-39 ("New code in ‹n› s") and Copy code, Passkey (`‹host› · ‹username›`, shown when the summary's `passkey` is true). Buttons Fill sign-in (MI11-40) and Fill code (MI11-28); help MI11-17.

INT-11.29 **Frame `extension-popup-search-everything`.** Typing sends `logins.search` with the field's text, at most 256 characters (INT-01.33), after the user stops typing for 300 ms (Larsal's own value: one request per pause, not one per key, so a fast typist does not fill INT-01.44's 8 places in flight); header MI11-41 with the result count; section MI11-42; rows with Copy username and Copy password; the help line MI11-43 names the page's host. A fill or copy of such an entry asks in Larsal (INT-02.22). Clear search (MI11-44) empties the field.

INT-11.30 **Frame `extension-popup-generator`** (INT-01.34; D-INT01-5). Kind tabs Password and Passphrase (MI11-100 d and k); the value from `password.generate` (with the chips' `options`, else the saved settings); the quality word and bits from `bits` (FEA-02.15's words, MI11-45); Length; the class chips `A–Z`, `a–z`, `0–9`, `!@#$`, `Äéß` (`classes`), "Leave out look-alikes l I 1 O 0" (`exclude_lookalike`); New password (regenerate), Copy (the value is already held), Fill on page (MI11-47: fills the focused new-password fields, INT-11.34's save rule then applies). The value is dropped when the popup closes or a new one comes.

INT-11.31 **Frame `extension-in-page-fill-menu`.** Shown under the clicked sign-in field (INT-11.13). Header MI11-48 (vault and match count), the page's matches (title, user name; ⏎ picks the selected row), "Fill one-time code next" (MI11-49, shown when the selected match has `code` true: after the sign-in fill, the next one-time code field of this tab on the same host gets the code frame at once), "Search ‹vault›…" (MI11-50: opens the toolbar popup on its search). For this item and INT-11.34's "Open the generator…", the frame page itself, inside its own click handler and before any `await`, sends `frame.popup` with the view and calls `browser.action.openPopup()`. A click there counts as a user action in Firefox ("Clicking a button on a page bundled with the extension", MDN, "User actions"), which Firefox before 149 requires for this call (BCD `webextensions.api.action.openPopup`); a call the background made after a relayed message would have none. These two items fill nothing, so they do not wait for INT-11.18's checks, whose round trip would end the user action. Where the call rejects, the frame shows MI11-99 in one line and stays open. A pick → INT-11.18's checks → `logins.get` → `fill`. The frame closes on Escape, a click outside, or the field's blur, unless focus moved into the frame itself (a click in the frame, or focus moved there for ⏎): once the blur has run, the content script finds its closed shadow root's `activeElement` is the frame's `iframe` (WHATWG HTML, `activeElement`: "when a child navigable is focused, its container is focused within its parent's active document"; the getter retargets against the shadow root it is asked on, so the page's own `document.activeElement` sees only the host) and keeps the frame open.

INT-11.32 **Frame `extension-in-page-one-time-code`.** Shown on a one-time code field (INT-11.16) when the user clicks it, or at once after "Fill one-time code next". Header MI11-51; the code of the one entry (from `code.get`, which Larsal allows only for an entry kept for the page, INT-02.23), `‹title› · ‹username›`, and the seconds left. A pick fills only the code field.

INT-11.33 **Errors in frames.** Every popup and in-page frame shows a failed request's words (INT-11.22) in one line under its header, never a dialog.

INT-11.34 **Frame `extension-in-page-new-password`.** Shown on a clicked new-password field. Header MI11-52, the row "Use a strong password" (MI11-53) with a value from `password.generate` (saved settings), "Open the generator…" (MI11-54: the popup on its Generator tab, opened as INT-11.31 says), help MI11-46 with the host, or MI11-46 b with the entry's title when INT-11.20 would update (a summary has the form's user name, or the form has no user name field and the page has exactly one summary). Use (⏎ or a pick, after INT-11.18's checks) fills the value into every new-password field of the form and marks the form, so its next submit follows INT-11.20's rule for a generated password: a save without a card, or the update frame. A page script cannot read the value before the fill: it exists only in the background and the frame page.

INT-11.35 **One in-page frame at a time** (B10; Larsal's own: every frame sits in the top layer, so a second Larsal frame would cover the first or the field the user types in, and a frame left on a tab the user is not looking at would wait there for a click). A tab shows at most one in-page frame; showing another closes the first. An in-page frame closes on Escape (WAI-ARIA Authoring Practices, Combobox pattern: "Escape: Dismisses the popup if it is visible", <https://www.w3.org/WAI/ARIA/apg/patterns/combobox/>, read 2026-11-01), a click outside it, its field's blur (the frames shown on a field: the fill menu, the one-time code frame and the new-password frame) unless focus moved into the frame itself (checked as INT-11.31 says; for every in-page frame), the page's document changing, or the tab going to the background; its token ends with it (INT-11.19). A save or update frame closed this way while its offer lives shows again as INT-11.20 says; Escape in it drops the offer.

INT-11.36 **Frame `extension-in-page-save-sign-in`.** Title MI11-55, Close; rows Title (`‹host› (‹username›)`, the form page's host without a leading `www.`, INT-11.20), Username, Password (masked, Show password), Group (from `groups.list`; default INT-02.26's default group); line MI11-56, with that user name as ‹username›, when the offer holds one (INT-11.20); buttons Never for this site (MI11-57), Not Now (MI11-58), Save (MI11-59, after INT-11.18's checks: `logins.save` with the offer's `url` and `form_url`, `username`, `password`, `title`, `group`). Not Now, Close and Escape drop the offer and its values (INT-11.20). The "Strong" mark of the locked frame is not shown (LD-191 (R01-4)).

INT-11.37 **Frame `extension-in-page-update-password`.** Title MI11-73 with the entry's title, the Entry row (`‹title› · ‹username›`), line MI11-74; buttons Not Now and Update (MI11-75, after INT-11.18's checks: `logins.update`); Larsal then asks its own MI02-07 unless S-BRW-16 is on (INT-02.25). `updated` false: the frame closes without words. The locked frame's "Reused", "Strong · 22 characters" and "eBay still uses it" are not shown (LD-191 (R01-4)).

INT-11.38 **Frames `extension-in-page-save-passkey` and `extension-in-page-sign-in-with-passkey`** (INT-11.21). Save: title MI11-76 with the RP host, the choices "Add to ‹title›" (an entry of the page's matches, MI11-77) and "New entry" (in the default group, MI11-78), buttons Use another device (MI11-79), Cancel, Save Passkey (MI11-80). Sign-in: title MI11-81, the matching passkey rows, line MI11-82, Use another device, Cancel, Continue (MI11-83). Each button counts only after INT-11.18's checks. What Larsal shows next follows INT-04 (R04-1).

INT-11.39 **Pairing words** (INT-02.5). The extension computes the same four words Larsal shows: `crypto.subtle.digest("SHA-256", …)` over the ASCII bytes `browser-bridge pairing v1`, then A, then C, then the identification public key (each 32 raw bytes); N = the first 8 bytes as an unsigned big-endian number (a `BigInt`); word i = line (N mod 7,776) of `words.txt`, the first line being line 0 (INT-02.5: "first entry 0"), then N = N div 7,776, for i = 1 to 4; shown in order, lower case. `words.txt` is the word column of Larsal's built-in list (FEA-03, `crates/larsal-core/src/generator/eff_large_wordlist.txt`), one word and one LF per line, written by `build.py`; its SHA-256 equals FEA-03's check value.

INT-11.40 **Page `extension-extension-options`.** Header MI11-84 with the browser's name and MI11-85 with the extension's version. Connection: Status MI11-86 (Larsal's version from the hello and the connection name from `check`) with the Connected mark (MI11-87), or MI11-88 when not reachable; Vaults (MI11-89 from `status`) with Open Larsal; Disconnect this browser (MI11-90, MI11-91) with Disconnect (MI11-92): after a click the extension sends `disconnect` (INT-01.30; LD-191, R01-1). On the reply, or on error 8 (no vault the request may use holds this key, INT-01.30; for example after the user disconnected this browser in Larsal, INT-02.8), the extension deletes the identification key (INT-11.6). On any other error it keeps the key and shows INT-11.22's words in one line (INT-11.33); for error 1 (the "Assoc." check found no usable vault, INT-01.30) that is MI11-104 (new, D-INT11-2) with the shown vault's name from `status`, or MI11-64 when `status` lists no vault. Vaults that were locked keep their item until disconnected in Larsal (INT-02.8). Filling: five switches kept in `storage.local` `options`, defaults as the locked frame: "Show the Larsal menu in sign-in fields" on, "Fill when a page loads" off with MI11-93, "Offer to save new sign-ins" on, "Offer to update changed passwords" on, "Use Larsal for passkeys" on with MI11-94. Shortcuts: the three commands with the keys `commands.getAll()` reports; in Chromium builds the row MI11-95 opens `chrome://extensions/shortcuts` (Edge: `edge://extensions/shortcuts`); other builds leave the row out. Privacy: MI11-96 and MI11-97.

INT-11.41 **Keyboard commands.** `_execute_action` "Open the Larsal popup", suggested `Alt+Shift+A` (⌥⇧A on a Mac); `fill-best-match` "Fill the best match", `Alt+Shift+F`: INT-11.13's frame, the first summary of `logins.find` (INT-03.14's order), `logins.get`, `fill`; nothing when there is no match; `generate-password` "Generate a password", `Alt+Shift+G`: the popup on its Generator tab. A command is the user's own action in the browser's chrome, which a page cannot fake.

INT-11.42 **The badge** (the locked design: the matches frame "Opens from the toolbar icon; the badge counts matches", `design/option-a/mockup.js`, LD-162). The toolbar badge shows the number of the active tab's top-frame matches from `logins.find` (summaries only, no dialog, D-INT01-9), nothing when there are none, and `!` after a safety close (INT-11.18) until the popup opens (Larsal's own: the one sign a page cannot cover that sends the user to the popup). It is set per tab with `action.setBadgeText` and its `tabId` ("Limits the change to when a particular tab is selected. Automatically resets when the tab is closed", Chrome, `action` API, read 2026-11-01) and cleared when the tab's document changes. The count has at most 3 digits (`logins.find` gives at most 200 entries, INT-02.20), within the "four or fewer characters" Chrome recommends.

INT-11.43 **Tests without a window** (B11; AGENTS.md rule 10). Pure modules (framing, the state of INT-11.23, field rules, the pairing words, the routing table's sender rules) run under macOS's `jsc` with injected bytes. Everything that needs WebCrypto, a page or the extension's APIs runs in the installed Chrome, headless, through E7-S7b's `extension/test/driver.py` (throwaway profile, test HOME, the `site-a.test`, `site-b.test` and `sub.site-a.test` pages) against Larsal with a test settings file. WebKit's rendering of the frames runs in an offscreen `WKWebView` in LarsalTests; Firefox runs headless with a throwaway profile (E7-S7j). Runs in real Safari and Firefox runs that need a window wait for the owner's go. No test starts a browser any other way.

INT-11.44 **The offer's site** (INT-11.20; INT-03.10; LD-295 (2): D-INT03-1 option (b) used in the extension, the list file and `tests/test_psl.txt` from github.com/publicsuffix/list only after the owner's yes, AGENTS.md rule 7; the Public Suffix List's "Formal algorithm", <https://github.com/publicsuffix/list/wiki/Format>, read 2026-11-01; Bitwarden compares the same registrable domain, its `Utils.getDomain` through `tldts` with `allowPrivateDomains: true`, `libs/common/src/platform/misc/utils.ts`). One module of the background finds a host's registrable domain by INT-03.10's rule:
- the rules are the ICANN and the private sections of `public_suffix_list.dat`; when no rule matches, the rule is `*`; an exception rule (`!`) wins and loses its leftmost label; else the matching rule with the most labels wins; a wildcard (`*.`) matches one label;
- the registrable domain is the public suffix plus one more label ("The registered or registrable domain is the public suffix plus one additional label"); a host that is itself a public suffix, an IP address, a one-label host and a host with an empty label have none;
- a Unicode rule is first turned to ASCII with the browser's own URL parser (`new URL("http://" + rule).hostname`, without its `!` or `*.`), because a tab's `url` holds an ASCII host (WHATWG URL).

`public_suffix_list.dat` is the list file of publicsuffix.org (MPL-2.0), kept unchanged in `extension/`. Larsal and the extension take one list version: the one Larsal's own list holds (INT-03.19), renewed with it at each Larsal release (LD-295 (2)). The file and the list project's `tests/test_psl.txt` (T83) come from a download, so they enter the project only after the owner's yes, together with LD-282's downloads (AGENTS.md rule 7, LD-295 (2)); until then T83 waits. The list decides only where a kept offer shows; it never decides which entry fits a page (INT-03 in Larsal). The module uses `URL`, so its test runs in the background through E7-S7b's driver.

### Messages

Larsal's own wording; IDs are ours; ‹…› marks a placeholder. Texts of the locked frames are kept word for word; rows marked "new" are states Option A does not draw (D-INT11-2).

| ID | Kind | Rule | Larsal text |
|---|---|---|---|
| MI11-01 | title | INT-11.22, INT-11.24 | Larsal is not reachable |
| MI11-02 | text | INT-11.24 | The extension talks only to the Larsal on this Mac. Check these, then try again. |
| MI11-03 | check | INT-11.24 | Larsal is installed |
| MI11-04 | hint | INT-11.24 | Version ‹version› in Applications (b, when no hello was ever answered: Install Larsal, or turn on ‹browser› in Larsal › Settings › Browser Integration — new) |
| MI11-05 | check | INT-11.24 | Larsal is running |
| MI11-06 | hint | INT-11.24 | Open Larsal, then click Try Again |
| MI11-07 | check | INT-11.24 | Browser Integration is on for ‹browser› |
| MI11-08 | hint | INT-11.24 | Settings › Browser Integration |
| MI11-09 | button | INT-11.24 | Try Again |
| MI11-10 | button | INT-11.23, INT-11.24, INT-11.27 | Open Larsal |
| MI11-11 | title | INT-11.25 | Connect ‹browser› to Larsal |
| MI11-12 | text | INT-11.25 | Switch to Larsal and allow the connection. Check that Larsal shows the same four words. |
| MI11-13 | status | INT-11.25 | Waiting for Larsal… |
| MI11-14 | button | INT-11.25 | Cancel |
| MI11-15 | title | INT-11.26 | ‹vault› is locked |
| MI11-16 | text | INT-11.26 | Unlock it in Larsal. You confirm with Touch ID in Larsal, so your vault password never goes through the browser. |
| MI11-17 | help | INT-11.13, INT-11.28 | Fills the username and password, then waits for you to press Sign in. |
| MI11-18 | button | INT-11.15 | Click again to copy (new) |
| MI11-19 | button | INT-11.26 | Unlock in Larsal |
| MI11-20 | menu | INT-11.26 | Other vaults: ‹names› |
| MI11-21 | header | INT-11.27 | ‹host› · ‹n› matches (b, for one match: ‹host› · 1 match — new) |
| MI11-22 | button name | INT-11.27 | Lock ‹vault› |
| MI11-23 | placeholder | INT-11.27 | Search ‹vault›… |
| MI11-24 | section | INT-11.27 | For ‹host› |
| MI11-25 | button | INT-11.27 | Fill |
| MI11-26 | button name | INT-11.27 | Copy password |
| MI11-27 | section | INT-11.27 | One-time code · ‹title› |
| MI11-28 | button | INT-11.27, INT-11.28 | Fill code |
| MI11-29 | button name | INT-11.27 | Copy code |
| MI11-30 | section | INT-11.27 | Recently used |
| MI11-31 | tab | INT-11.27 | Entries |
| MI11-32 | tab | INT-11.27 | Codes |
| MI11-33 | tab | INT-11.27 | Generator |
| MI11-34 | tab | INT-11.27 | Settings |
| MI11-35 | button name | INT-11.28 | Back |
| MI11-36 | button name | INT-11.28 | Open in Larsal |
| MI11-37 | button name | INT-11.28 | Copy username |
| MI11-38 | button name | INT-11.28 | Show password |
| MI11-39 | line | INT-11.28 | New code in ‹n› s |
| MI11-40 | button | INT-11.28 | Fill sign-in |
| MI11-41 | header | INT-11.29 | ‹n› results in ‹vault› (b, for one: 1 result in ‹vault› — new) |
| MI11-42 | section | INT-11.29 | All entries |
| MI11-43 | help | INT-11.29 | These do not match ‹host›, so Larsal asks before filling them here. |
| MI11-44 | button name | INT-11.29 | Clear search |
| MI11-45 | line | INT-11.30 | ‹quality word› · ‹bits› bits (the quality word is MI11-102; the frame's tabs and labels are MI11-100 d and k to o) |
| MI11-46 | help | INT-11.34, INT-11.20 | Larsal saves it as a new entry for ‹host› once you continue. (b, when INT-11.20 would update: Larsal offers to update ‹title› once you continue. — new) |
| MI11-47 | button | INT-11.30 | Fill on page |
| MI11-48 | header | INT-11.31 | Larsal · ‹vault› · ‹n› matches (b, for one: Larsal · ‹vault› · 1 match — new) |
| MI11-49 | item | INT-11.31 | Fill one-time code next |
| MI11-50 | item | INT-11.31 | Search ‹vault›… |
| MI11-51 | header | INT-11.32 | Larsal · one-time code |
| MI11-52 | header | INT-11.34 | Larsal · new password |
| MI11-53 | item | INT-11.34 | Use a strong password |
| MI11-54 | item | INT-11.34 | Open the generator… |
| MI11-55 | title | INT-11.36 | Save this sign-in? |
| MI11-56 | line | INT-11.20, INT-11.36 | ‹host› already has an entry for ‹username›. This adds a second one. |
| MI11-57 | button | INT-11.36 | Never for this site |
| MI11-58 | button | INT-11.36, INT-11.37 | Not Now |
| MI11-59 | button | INT-11.36 | Save |
| MI11-60 | text | INT-11.5 | This browser is too old for Larsal. Update ‹browser› to version ‹version› or later. (new) |
| MI11-61 | line | INT-11.25 | Larsal did not allow this connection. (new) |
| MI11-62 | line | INT-11.3 | Larsal fills this page only from here. To see Larsal's menu in the page, allow the Larsal extension on all sites in ‹browser›'s extension settings. (new) |
| MI11-63 | line | INT-11.18 | Larsal closed its menu on this page because something covered it. Fill from here instead. (new) |
| MI11-64 | line | INT-11.22, INT-11.23, INT-11.40 | No vault is open in Larsal. (new) |
| MI11-65 | line | INT-11.22 | Stopped in Larsal. Nothing was filled. (new) |
| MI11-66 | line | INT-11.22 | Larsal has no entry for this page. (new) |
| MI11-67 | line | INT-11.22 | This entry can't be used on this page. (new) |
| MI11-68 | line | INT-11.22 | Larsal can't save a value that holds a placeholder or a reference. (new) |
| MI11-69 | line | INT-11.22 | Larsal is busy. Try again in a moment. (new) |
| MI11-70 | line | INT-11.22 | That is too long for Larsal. (new) |
| MI11-71 | line | INT-11.22 | Something went wrong. Try again. (new) |
| MI11-72 | line | INT-11.27 | Larsal has no entry for ‹host›. (new) |
| MI11-73 | title | INT-11.37 | Update the password for ‹title›? |
| MI11-74 | line | INT-11.37 | The old password goes to the entry's history. |
| MI11-75 | button | INT-11.37 | Update |
| MI11-76 | title | INT-11.38 | Save a passkey for ‹host›? |
| MI11-77 | choice | INT-11.38 | Add to ‹title› (b, its line: ‹username› · the entry keeps its password) |
| MI11-78 | choice | INT-11.38 | New entry (b, its line: In ‹group›) |
| MI11-79 | button | INT-11.38 | Use another device |
| MI11-80 | button | INT-11.38 | Save Passkey |
| MI11-81 | title | INT-11.38 | Sign in to ‹host› with a passkey |
| MI11-82 | line | INT-11.38 | Larsal confirms with Touch ID before it signs in. |
| MI11-83 | button | INT-11.38 | Continue |
| MI11-84 | title | INT-11.40 | Larsal for ‹browser› |
| MI11-85 | line | INT-11.40 | Version ‹version› · works with Larsal on this Mac |
| MI11-86 | line | INT-11.40 | Connected to Larsal ‹version› as “‹name›” |
| MI11-87 | mark | INT-11.40 | Connected |
| MI11-88 | line | INT-11.40 | Not connected (new) |
| MI11-89 | line | INT-11.40 | ‹vault› unlocked · ‹vaults› locked |
| MI11-90 | label | INT-11.40 | Disconnect this browser |
| MI11-91 | line | INT-11.40 | Larsal forgets this browser. You can connect again later. |
| MI11-92 | button | INT-11.40 | Disconnect |
| MI11-93 | hint | INT-11.40 | Off is safer: a page could hide fields to catch a fill. |
| MI11-94 | hint | INT-11.40 | ‹browser› asks Larsal first when a site wants a passkey. |
| MI11-95 | label | INT-11.40 | Change them in chrome://extensions/shortcuts |
| MI11-96 | label | INT-11.40 | The extension stores no passwords |
| MI11-97 | line | INT-11.40 | It asks Larsal for each fill over an encrypted channel and keeps nothing after the tab closes. |
| MI11-99 | line | INT-11.22, INT-11.31, INT-11.34 | Click the Larsal button in ‹browser›'s toolbar. (new) |
| MI11-103 | line | INT-11.26 | Larsal does not open its unlock panel for browsers. Unlock ‹vault› in Larsal. (new) |
| MI11-104 | line | INT-11.22, INT-11.40 | Unlock ‹vault› in Larsal, then disconnect again. (new) |
| MI11-105 | line | INT-11.22, INT-11.33 | Unlock ‹vault› in Larsal, then try again. (new) |
| MI11-100 a | title | INT-11.40 | Larsal · Options |
| MI11-100 b | button | INT-11.40 | Open |
| MI11-100 c | label | INT-11.28, INT-11.36 | Username |
| MI11-100 d | label, tab | INT-11.28, INT-11.30, INT-11.36, INT-11.37 | Password |
| MI11-100 e | label | INT-11.28 | One-time code |
| MI11-100 f | label | INT-11.28 | Passkey |
| MI11-100 g | label | INT-11.36 | Title |
| MI11-100 h | label | INT-11.36 | Group |
| MI11-100 i | label | INT-11.37 | Entry |
| MI11-100 j | button name | INT-11.36, INT-11.37, INT-11.38 | Close |
| MI11-100 k | tab | INT-11.30 | Passphrase |
| MI11-100 l | label | INT-11.30 | Length |
| MI11-100 m | label | INT-11.30 | Leave out look-alikes l I 1 O 0 |
| MI11-100 n | button | INT-11.30 | Copy |
| MI11-100 o | button name | INT-11.30 | New password |
| MI11-100 p | line | INT-11.32 | ‹n› s |
| MI11-100 q | pill | INT-11.38 | passkey |
| MI11-101 a | name | INT-11.23 | Larsal |
| MI11-101 b | field name | INT-11.27, INT-11.29 | Search entries |
| MI11-101 c | name | INT-11.30 | Password generator |
| MI11-101 d | frame name | INT-11.31 | Fill from Larsal |
| MI11-101 e | frame name | INT-11.36 | Save this sign-in |
| MI11-101 f | frame name | INT-11.37 | Update password |
| MI11-101 g | frame name | INT-11.38 | Save passkey |
| MI11-101 h | frame name | INT-11.38 | Sign in with a passkey |
| MI11-101 i | switch name | INT-11.40 | Inline menu |
| MI11-101 j | switch name | INT-11.40 | Autofill on load |
| MI11-101 k | switch name | INT-11.40 | Save prompt |
| MI11-101 l | switch name | INT-11.40 | Update prompt |
| MI11-101 m | switch name | INT-11.40 | Passkeys |
| MI11-102 a | word | INT-11.30 | Poor |
| MI11-102 b | word | INT-11.30 | Weak |
| MI11-102 c | word | INT-11.30 | Good |
| MI11-102 d | word | INT-11.30 | Excellent |

MI11-100 and MI11-101 are the locked frames' other visible labels and accessible names (`design/option-a/manifest.json`, `texts` and `accessibleNames`); MI11-102 a to d are FEA-02.15's quality words, from its bands (below 40 bits, 40 to below 75, 75 to below 100, 100 and up). Labels of the options page's other rows are their locked frame texts ("Connection", "Status", "Vaults", "Filling", "Shortcuts", "Privacy", the five switch labels, the three command names), as messages MI11-98 a to MI11-98 n in that order (6, 5 and 3: 14 texts).

## Edge cases and errors

- **The browser restarts or the worker sleeps:** the port closes (Chrome-family), the session ends; the next need says hello again (INT-11.8). Nothing is kept across it but the identification key and `storage.local`.
- **Two windows of one Chromium profile:** one background, one port, one session.
- **Two browser profiles:** two extensions with two identification keys; each connects on its own (INT-01, "The same extension with two ports").
- **Larsal's key gives an all-zero X25519 result:** WebCrypto throws; the background drops the session and reports Larsal as not reachable after one more try (INT-11.7).
- **A reply with an unknown `req`, a wrong nonce or a box that does not open:** dropped; the request waits for its own reply or its timeout (INT-11.10).
- **A page removes or moves Larsal's host element:** the MutationObserver sees it, the frame closes, nothing fills (INT-11.18).
- **A page opens its own popover over the menu:** check 3 fails at the click; nothing fills; MI11-63.
- **A frame navigates between the pick and the fill:** the fill goes by `documentId` where the browser has it, and the content script compares its origin (INT-11.15); nothing fills.
- **An `about:blank`, `data:` or `blob:` iframe with a password field:** no content script runs there; never filled (INT-11.16).
- **A sandboxed `http` or `https` iframe with a password field:** the content script may run there, but its origin is opaque, so the background refuses its messages (INT-11.11); no menu, never filled (INT-11.16).
- **The page's CSP blocks the passkey page script:** the browser's own WebAuthn flow runs (INT-11.21).
- **Firefox user took the host permissions back:** MI11-62; the popup fills the tab it was opened on (`activeTab`), no in-page menu shows anywhere.
- **`words.txt` missing or changed:** `build.py`'s test of INT-11.39 fails the build; a wrong list would show words that differ from Larsal's, and the user would deny.
- **A form that loads a new page on submit:** the save or update offer shows again in the tab's next document on the same site, for up to 150 s (INT-11.20); a page of another site in between drops it.
- **A form inside an iframe of another site:** its offer's site is the iframe's; it shows again only when the tab's top frame shows a document of that site, else it ends after 150 s (INT-11.20).
- **Paired browser, vault locked:** `check` gives 8, but the locked frame shows and no `connect` is sent (INT-11.23).
- **Larsal updates while the browser runs:** the port closes when Larsal quits; the next hello reaches the new Larsal; `last_app_version` changes.

## Lead decisions

| ID | Question | Options | Recommended, with evidence |
|---|---|---|---|
| D-INT11-1 | What "Open Larsal" and "Open in Larsal" do (frames `extension-popup-app-not-reachable`, `-matches-for-this-site`, `-entry`, `extension-extension-options`). With Larsal not running or integration off nothing reaches Larsal over INT-01 (44, 45), and no request opens Larsal's window | (a) Larsal registers one URL scheme, `app.larsal.desktop` (its bundle id, renamed with D1), whose only URL `app.larsal.desktop://open` brings Larsal to the front and does nothing else; the extension opens it with `tabs.create`, and the browser asks the user first; "Open in Larsal" does the same (no entry is chosen, so a web page that opens the URL gains nothing); (b) leave the buttons out (a mockup change) | (a). It is the only way a browser extension can start a Mac app; the scheme takes no parameter, so a page cannot steer Larsal. Apple, "Defining a custom URL scheme for your app" (developer.apple.com/documentation/xcode/defining-a-custom-url-scheme-for-your-app); RFC 3986 section 3.1 allows dots in a scheme. Larsal's Info.plist gains `CFBundleURLTypes` (E7-S6). Check with Verify: which browsers ask before an outside scheme, in a throwaway profile |
| D-INT11-2 | States Option A does not draw (rows marked "new" in Messages: MI11-04 b, MI11-18, MI11-21 b, MI11-41 b, MI11-46 b, MI11-48 b, MI11-60 to MI11-72, MI11-88, MI11-99, MI11-103, MI11-104, MI11-105) and the popup's state with no vault open (INT-11.23: MI11-64 in one line with Open Larsal); the parts of locked frames this card leaves out under LD-191 (R01-4) ("Strong" in the save frame; "Reused", "Strong · 22 characters" and "eBay still uses it" in the update frame) and the save frame's title form (`‹host› (‹username›)`, the frame shows "Reddit (alex_morgan_dev)"); and two problems in locked texts. (1) The options page's five switches have accessible names (MI11-101 i to m: "Inline menu", "Autofill on load", "Save prompt", "Update prompt", "Passkeys") that do not hold their visible labels (MI11-98 g to k, such as "Show the Larsal menu in sign-in fields"), which fails WCAG 2.2 success criterion 2.5.3 Label in Name (Level A: "For user interface components with labels that include text or images of text, the name contains the text that is presented visually", <https://www.w3.org/TR/WCAG22/#label-in-name>, read 2026-11-01). (2) MI11-95 names `chrome://extensions/shortcuts` in the Edge build too, where INT-11.40 opens `edge://extensions/shortcuts` | (a) Draw them in `design/option-a/proposals.html` with E7-S7k for the owner's one-pass review (AT-K05), never blocking the build; (b) add them to the locked file | (a), as LD-268 does for other additions; the lead adds them to the one owner item of R01-5. For the two problems, propose there: (1) each switch's accessible name is its visible label (MI11-101 i to m are dropped; WCAG's note: "A best practice is to have the text of the label at the start of the name"); (2) MI11-95 reads "Change them in ‹shortcuts page›", with the page each build opens (INT-11.40). Until the owner answers, the build uses the locked texts |
| D-INT11-3 | The locked frame's "Other vaults: Work, Family" menu: INT-01 has no request that changes Larsal's shown vault | (a) The menu only lists the other open vaults and their states; (b) a new request `vault.show` | (a). With S-BRW-14 on, unlocked other vaults are used anyway (INT-02.10); a request that moves Larsal's window at a browser's word is not needed for a fill |

## Security notes

- **What the extension never does:** store a password or any vault data; fill without a user action (except INT-11.14's narrow case); fill into a frame other than the one the user acted on; take a page's word for its URL or origin; run code that is not in its own files; build markup from strings; make a network request; show a master password field.
- **Channel keys** are non-extractable WebCrypto keys; the X25519 secrets never become JavaScript values (INT-11.7). The identification key cannot be read by any script; a same-user program that reads the browser's profile files or memory may still take it (out of scope, plan/security.md).
- **Clickjacking** (AT-F09): INT-11.18 runs all of Toth's proposed checks, and on any doubt sends the user to the toolbar popup, which the page cannot cover. Known limits: a page's popovers inside its own closed shadow roots cannot be listed (check 3), and `elementsFromPoint` does not see `pointer-events: none` popovers (Toth), which is why checks 1 to 3 and 5 run too.
- **A copy of a frame page** (INT-11.19): a page that somehow learned a menu token and loads its own copy of a `frames/` page with it is caught when Larsal's own frame says `frame.ready`; a pick in the copy before that moment is a known limit. E7-S7m tries it.
- **A kept save or update offer** (INT-11.20) holds the typed user name and password in the background's memory for at most 150 s, never in a store, and its open frame closes when it is dropped; it shows only in a document of its own site whose origin the content script checks, inside the closed shadow root.
- **Invisible forms** (Princeton CITP): hidden fields are never offered or filled (INT-11.16), and nothing fills without a user action.
- **Subdomains** (Toth: an XSS on any subdomain is enough): every fill needs a real click or command, and Larsal's INT-02 and INT-03 decide which entries fit; whether a fill on a host other than the stored one should ask is open (research section 18); E7-S7m tries it on `sub.site-a.test`.
- **Copy** in the popup puts a password on the system clipboard, which the extension cannot clear later (no clipboard-read permission); Larsal's own clipboard rules (APP-03) do not reach it. The user copies only by clicking.
- **Pairing words** let the user tell Larsal's real Connect dialog from one another program raised (INT-02.5, AT-F04).
- **Two Checkers** review the channel code (E7-S7c, team.md: crypto).

## Test cases

All tests run without a window and never touch the owner's browser profiles or Library (AGENTS.md rule 10): browser tests go through E7-S7b's `extension/test/driver.py` (headless Chrome, throwaway profile, test HOME under `/tmp`, the test sites), Larsal runs hidden with a test settings file and a test HOME, WebKit rendering runs in an offscreen `WKWebView` in LarsalTests, and pure modules run under `jsc`.

| Case | Given | When | Then |
|---|---|---|---|
| T01 INT-11.1 | Each package `build.py` writes (no `test/` folder: each package holds only the files it uses, INT-11.2) | Search every file for `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`, `eval(`, `new Function`, `fetch(` not followed by `browser.runtime.getURL(`, `XMLHttpRequest`, `WebSocket`, `EventSource`, `sendBeacon`, `onMessageExternal`, `onConnectExternal`, `http://` or `https://` outside the manifest's host permissions, INT-11.44's one `"http://" + rule` and the comment lines (`//`) of `public_suffix_list.dat`, `import` in a content script | None found; no `package.json`, no minified file |
| T02 INT-11.1 | A demo page whose entry title is `<img src=x onerror=alert(1)>` | The popup and the fill menu draw it | The tag shows as text; no element is made; no script runs |
| T03 INT-11.2 | `build.py` | Build Chrome, Edge, Firefox and Safari | Each `manifest.json` has the members of INT-11.2's table; Chrome and Edge `minimum_chrome_version` `"133"`; Firefox `strict_min_version` `"140.0"` and `data_collection_permissions` `{"required":["none"]}`; Safari `strict_min_version` `"18.4"`; `key` only in development builds |
| T04 INT-11.2 | The four builds | Read `content_security_policy` | `extension_pages` is exactly `script-src 'self'; object-src 'self'` |
| T05 INT-11.3 | The four builds | Read the permission members | Exactly `nativeMessaging`, `storage`, `activeTab`, `scripting`, `http://*/*`, `https://*/*`; no `optional_permissions`, no `externally_connectable` |
| T06 INT-11.4, INT-11.2 | Development build with the `key` member | Load it twice through the driver with two throwaway profiles | The same extension id both times; Larsal's debug manifest lists it |
| T07 INT-11.5 | Test build where `generateKey` for X25519 rejects (test seam in the background) | Open the popup | MI11-60 naming Chrome and 133; no port was opened (the echo host saw nothing) |
| T08 INT-11.6 | First hello against Larsal | Read IndexedDB `bridge`/`keys`/`identification` from the background | A `CryptoKeyPair`; `privateKey.extractable` false; `exportKey("raw" or "pkcs8" or "jwk", privateKey)` rejects; the public key exports as 32 bytes |
| T09 INT-11.6 | Connected profile | Search `storage.local`, every message sent to content scripts and frames, and the console log | The identification key's public or secret bytes never appear outside IndexedDB and `id_key` |
| T10 INT-11.6 | Connected profile | Delete the IndexedDB record; open the popup | A new key is made; `check` gives 8; the first-connection frame shows |
| T11 INT-11.7, INT-01.50 | INT-01.50's published vectors and channel vectors CV-1 to CV-9 | Compute each in WebCrypto in headless Chrome (E7-S7c) | Every output equals INT-01.50's value byte for byte |
| T12 INT-11.7 | A session | Read the background's session object | Its keys are `CryptoKey` objects with `extractable` false; the request key's usages are `encrypt` only, the reply key's `decrypt` only; no `ArrayBuffer` holds an X25519 result |
| T13 INT-11.7 | A fake Larsal (test host) that answers the hello with an all-zero key | Hello | `OperationError` in the background; one more hello; then the popup shows the not-reachable frame |
| T14 INT-11.8 | Larsal not running; the echo of 44 | Open the popup; start Larsal (test HOME); wait | Not-reachable frame first; within 2 seconds of Larsal listening the popup shows the matches or first-connection frame without a reload |
| T15 INT-11.8 | No host manifest in the test HOME | Background starts; then open the popup three times | `connectNative` fails; no more than one retry per need (the driver counts port opens: at most 2 per need) |
| T16 INT-11.8 | Session open | Kill `larsal-bridge` by PID | `onDisconnect`; a new port and a new hello; requests in flight fail as not reachable |
| T17 INT-11.9 | E7-S7e: the Safari handler test with a test socket folder | `status` 16 minutes after the last request | Plain error 3; the extension says hello again, sends `check`, then `status` once more and shows the answer |
| T18 INT-11.10 | Session; the test Larsal holds a `logins.find` reply | Send 9 requests | 8 in flight, the 9th waits in the queue and is sent when one answers; Larsal never sees 9 at once |
| T19 INT-11.10 | Session | The test Larsal sends a reply with an unknown `req`, then one whose nonce differs from its request's, then one sealed with the request key | All three dropped; the request still gets its real reply |
| T20 INT-11.10 | Session | The test Larsal answers `status` with plain error 41 | One new hello, one `check`, one resent `status`; a second 41 shows the not-reachable frame |
| T21 INT-11.10 | Session; the test Larsal never answers `status` | Wait | After 60 seconds the request fails as not reachable; a waiting `connect` has no such limit |
| T22 INT-11.11 | A content script on `https://site-a.test/` | It sends `fields.found` with a body that says `url: "https://site-b.test/"` and `origin: "https://site-b.test"` | `logins.find` goes with `url` `https://site-a.test/…` from `MessageSender`; the body's values change nothing |
| T23 INT-11.11, INT-11.16 | A sandboxed `https` iframe (`sandbox="allow-scripts allow-forms"`, opaque origin) with a password field on `site-a.test` | Its content script sends `fields.found`; then a trusted click in the field | Refused, no reply, no menu, no request to Larsal; the field is never filled |
| T24 INT-11.12 | A content script | It sends `popup.get` and `frame.pick` | Both refused (wrong sender kind); nothing reaches Larsal |
| T25 INT-11.12 | An in-page frame page | It sends `frame.pick` with a token of another tab | Refused |
| T26 INT-11.13 | `site-a.test` with one allowed match; "Fill when a page loads" off | Load the page; the page calls `field.focus()` and dispatches synthetic `click` and `keydown` events | No menu opens and nothing fills; no `logins.get` reaches Larsal |
| T27 INT-11.13 | Same | A trusted click in the user name field (driver input event), then a trusted click on the match | The menu opens; after the click the user name and password are filled; no form is submitted |
| T28 INT-11.13 | A `site-b.test` iframe with a sign-in form in a `site-a.test` page, entry for `site-b.test` allowed | Click in the iframe's field, pick the entry | `logins.get` carries `url` of the iframe and `top_url` of the page; Larsal shows INT-02.19's prompt; without Allow nothing fills |
| T29 INT-11.14 | Option on; `https://site-a.test/` top page with one allowed match | Load the page | One `logins.get` and one fill; reload: one more (a new document) |
| T30 INT-11.14 | Option on | The same page over `http://`; a page with two matches; one match in state `ask`; the form in a `site-b.test` iframe | No fill in any case; Larsal opens no dialog |
| T31 INT-11.15 | A pick filled the form | Read the background's state and every store | No password or user name is held; `storage.local` holds only `options`, `never_save`, `last_app_version` |
| T32 INT-11.15, INT-11.12 | A frame that navigates to `site-b.test` between pick and fill (test seam delays the reply); Chrome headless, then Firefox 140 headless (E7-S7j) | The fill message arrives | Nothing filled (origin differs). Chrome: the `tabs.sendMessage` options hold `frameId` and `documentId`. Firefox 140: they hold only `frameId`, the call does not reject, and every `fill`, `menu.check` and `frame.show` of the other tests reaches its frame |
| T33 INT-11.15 | Popup entry frame; the entry is allowed | Click Copy password before the value is held, then again | First click: `logins.get`, button MI11-18, the clipboard (driver's private check) unchanged; second click writes the value; after the popup closes the background holds nothing |
| T34 INT-11.16 | Field rules under `jsc` | Forms: a password with a user name before it; `autocomplete="new-password"`; two password fields; `autocomplete="one-time-code"`; a password field with `opacity:0`; one of zero size; one in `display:none` | Kinds found as INT-11.16 says; the hidden ones are not offered |
| T35 INT-11.16 | An `about:blank` iframe with a password field written by the page | Click in it | No content script there; no menu; nothing fills |
| T36 INT-11.17 | The fill menu shown | A page script walks the DOM and every open shadow root, and reads the host's `shadowRoot` | No title, user name or URL of an entry is found; `shadowRoot` is null |
| T37 INT-11.17 | The menu shown | Read the iframe's `src` from inside the content script | The frame URL is the extension's dynamic URL; in Chrome a second browser start gives another URL |
| T38 INT-11.18, AT-F09 | The menu shown on `site-a.test` | The page sets `opacity:0` on the host; then on `html`; then on `body`; then shows a full-page overlay with `pointer-events:none`; then opens its own popover; then sets `filter:opacity(0)` on `body`; then appends an element after the host; each time a trusted click lands on a match | Every time: the menu closes, nothing fills, no `logins.get` reaches Larsal, the badge shows `!`, the next popup shows MI11-63 |
| T39 INT-11.18 | The menu shown, nothing changed | Trusted click on a match | Checks pass; the fill happens |
| T40 INT-11.19 | The menu shown; its token copied by a test hook into a second tab's frame page | That frame sends `frame.pick`; then the first tab's frame sends `frame.pick` 10 minutes after the token was issued (test clock). Again with a new menu: a test hook loads a second, hidden copy of the fill-menu page with the same token in the same tab; it sends `frame.ready`, then `frame.pick`; then Larsal's own frame sends `frame.pick`. Again with the copy's `frame.ready` sent before Larsal's own frame's | Refused (other tab); refused (token ended); the token is 16 bytes. The copy's `frame.ready` and `frame.pick` are refused, the token ends, the menu closes, and Larsal's own frame's `frame.pick` is refused too; no `logins.get` reaches Larsal. The copy first: Larsal's own frame's `frame.ready` is refused, the token ends, and no pick of either frame counts |
| T41 INT-11.20 | `site-a.test` sign-up form, no match, save on | Type a user name and password; submit. Again, and the test Larsal answers the first `logins.save` with error 42. Again, with the test Larsal holding the first `logins.save` unanswered: two more trusted clicks on Save, then the test Larsal answers | The save frame shows; Not Now: nothing reaches Larsal; again with Save: one `logins.save` with the typed values. Error 42: the frame stays, with MI11-69 in one line; Save again sends a second `logins.save`, and its reply closes the frame. Held: Larsal's request log has one `logins.save`, and the reply closes the frame |
| T42 INT-11.20 | A match with user name `demo` | A sign-in form submitted with `demo` and a password | No card; nothing reaches Larsal |
| T43 INT-11.20 | A change-password form (`autocomplete="new-password"`), a match `demo` | Submit with `demo` and a new password | The update frame; Update sends `logins.update`; Larsal's MI02-07 follows (test answerer) |
| T44 INT-11.20 | Save frame shown | Never for this site; submit again; then, with 1,000 hosts already in `never_save`, Never for one more site | `never_save` holds the host; no card the second time; the list still holds 1,000 hosts, the oldest one gone |
| T45 INT-11.20, INT-11.34 | A sign-up form | Use in the new-password frame; submit | One `logins.save` without a card |
| T46 INT-11.21 | E7-S7i: WebAuthn virtual authenticator, `site-a.test` | Register and sign in with a passkey kept in Larsal | `passkey.create` and `passkey.get` carry `origin` `https://site-a.test` from `MessageSender` |
| T47 INT-11.21 | A page script that posts a message claiming `origin` `https://site-b.test` | Passkey request | The claim is ignored; `origin` is the sender's |
| T48 INT-11.21 | Larsal not running; then Larsal says no; then Use another device | `navigator.credentials.create` | Each time the browser's own flow runs (the virtual authenticator gets the call) |
| T49 INT-11.22 | `_locales/en/messages.json`; every frame drawn by the driver | Compare with this card's Messages table; read every shown text and every accessible name of each frame | Every MI11 id and every lettered text (`MI11-04 b` and every other b text, MI11-98 a to n, MI11-100 a to q (q: the sign-in passkey frame's "passkey" pill), MI11-101 a to m, MI11-102 a to d) has a message, named as INT-11.22 says (`MI11_04_b`, `MI11_100_a`); every name holds only `A-Z`, `a-z`, `0-9` and `_`; every shown text and accessible name comes from a message, except the vault data, key marks, badge and joins INT-11.22 names |
| T50 INT-11.22 | The test Larsal answers each boxed error number | Ask from the popup | Each shows INT-11.22's message; no error shows Larsal text |
| T51 INT-11.23 | State fakes (test seam) for each row of INT-11.23; then the shown vault locked and `check` error 8 at once | Open the popup | The frame of that row shows; with both, the locked frame |
| T52 INT-11.24 | No host; then 44; then 45 | Open the popup | Marks: failed/unknown/unknown; done/failed/unknown; done/done/failed; hints as INT-11.24 |
| T53 INT-11.25 | A new profile; Larsal with V unlocked | Open the popup | `connect` sent; the frame shows four words equal to Larsal's dialog words (test reads both); Connect in Larsal (test seam) → the matches frame |
| T54 INT-11.25, INT-11.10 | The first-connection frame, port route (Chrome) | Cancel; then open the popup again | A new hello on the same port reaches Larsal; Larsal's dialog closes as Deny; the popup closes; nothing stored; the old `connect` is dropped from the background's `req` table at once. The reopened popup shows the first-connection frame, and Larsal's request log has exactly one new `connect` |
| T55 INT-11.25 | Larsal's dialog answered Deny | — | MI11-61 with Try Again |
| T56 INT-11.26, INT-11.23, INT-11.10 | A paired profile (proven for V); V locked. Then a new profile, V locked | Open the popup; Unlock in Larsal | Paired: the locked frame shows, not the first connection; Larsal's request log has `status`, `check` (error 8) and `unlock`, and no `connect`; after the unlock the background sends `status` and `check` again and the matches frame shows. New profile: the locked frame; after the unlock `check` gives 8, the first-connection frame shows and exactly one `connect` is sent |
| T57 INT-11.27 | `site-a.test` with two matches, one with a code | Open the popup | Header MI11-21 with 2; both rows; the code row with a code from `code.get`; recent rows; badge 2 |
| T58 INT-11.28 | The entry frame | Show password; close the popup | The password shows; after closing, nothing held |
| T59 INT-11.29 | Search | Type 300 characters; then type 5 keys 100 ms apart (test clock) | The request's `text` has 256 characters; results without secrets; a fill asks in Larsal; the 5 keys send one `logins.search`, 300 ms after the last key |
| T60 INT-11.30 | Generator tab, length 20, chips A–Z and 0–9 | Open | `password.generate` with `{"kind":"password","options":{"length":20,"classes":["upper","digits"],"exclude_lookalike":…}}`; quality word and bits from `bits` |
| T61 INT-11.31 | Fill menu with "Fill one-time code next" | Pick the entry; the next page on the same host has a one-time code field | The code frame shows at once; a pick fills only the code field |
| T62 INT-11.32 | A one-time code field on `site-b.test` while the entry fits `site-a.test` | Click the field | `code.get` gets error 18; MI11-67; nothing filled |
| T63 INT-11.33 | Any failed request in a frame | — | One line under the header; no dialog opens |
| T64 INT-11.34 | New-password frame | A page script reads every field value and the DOM before Use | The generated value is not found |
| T65 INT-11.36 | Save frame | Read the frame | No strength mark; title `site-a.test (demo)`; Group from `groups.list` |
| T66 INT-11.37 | Update frame | Read it | No "Reused" or strength line; MI11-74 shows |
| T67 INT-11.38 | Passkey frames shown | The page hides the host (opacity 0), then a trusted click on Save Passkey | Nothing sent to Larsal (INT-11.18) |
| T68 INT-11.39 | Fixed A, C and identification key (INT-01.50's CV keys) | Compute the words in the extension and in Larsal; then under `jsc`, the word step alone with N = 0 and N = 7,775 | The same four words; `words.txt` has 7,776 lines and FEA-03's check value; N = 0 gives `words.txt`'s first line, N = 7,775 its last |
| T69 INT-11.40 | Options page, connected | Disconnect. Again, with the test Larsal answering error 8 (the browser already disconnected in Larsal). Again, with error 1 (S-BRW-14 off, the shown vault V locked). Again, with error 1 and no vault open | `disconnect` sent; on the reply the IndexedDB record is gone; the next popup starts a first connection. Error 8: the record is gone and no words show. Error 1: the record stays and MI11-104 with V's name shows in one line; with no vault open, MI11-64 |
| T70 INT-11.40 | A new profile | Read `storage.local` `options` after the first start | Menu on, fill on load off, save on, update on, passkeys on |
| T71 INT-11.41 | The driver sends the "Fill the best match" command on a page with two matches | — | The first match (INT-03.14 order) fills the focused frame; a page with none: nothing sent |
| T72 INT-11.42 | `site-a.test` with two matches | Load; open a second tab on `site-b.test` (no match); go back to the first tab; navigate it to `site-b.test` | Badge 2; empty on the second tab; 2 again on the first; then empty. Every `action.setBadgeText` call carries a `tabId` |
| T73 INT-11.43 | Every test run above | Watch windows and focus (E7-S7b's guard) and the owner's files' modification times | No window shows, focus never moves, nothing of the owner's changes |
| T74 INT-11.35, INT-11.31 | The fill menu shown under the focused user name field | A trusted click on a match; again with focus moved into the menu and ⏎; again with a trusted click on the page's body; then, with a new menu, click in a one-time code field of the same page, and a trusted click on the code in the code frame; again, and switch tabs; then click in a new-password field of the page, and a trusted click on "Use a strong password" | The field's blur does not close a frame when focus went into it: the click and the ⏎ in the menu each fill, the click in the code frame fills the code field, and the click in the new-password frame fills the value. The click on the body closes the menu. The menu closes when the code frame shows; the code frame closes on the tab switch; the closed frames' tokens are dead (a `frame.pick` with any of them is refused) |
| T75 INT-11.3 | Firefox headless (E7-S7j), the host permissions taken back; tabs on `site-a.test` and `site-b.test` | Open the popup on the `site-a.test` tab; Fill | MI11-62 shows; the content scripts run only in that tab and the fill works there; clicking a field in the `site-b.test` tab opens no menu |
| T76 INT-11.20, INT-11.34 | A change-password form on `site-a.test` (user name field `demo`, a field with `autocomplete="new-password"`), a match `demo`, update on | Use in the new-password frame; submit | The frame's help is MI11-46 b; no `logins.save`; the update frame shows; Update sends one `logins.update` for the `demo` entry. Again on a form with no user name field and exactly one match: the same. Again with "Offer to update changed passwords" off: the help is still MI11-46 b, the update frame still shows, and Update sends one `logins.update` |
| T77 INT-11.12 | The options page open in its tab; a frame page under `frames/` in an iframe with a live token; the same frame page loaded as a tab's top page | Each sends `options.status`; both frame pages send `frame.ready` | The options page gets its answer (`sender.tab` set, `frameId` 0); the iframe's `options.status` is refused and its `frame.ready` is taken; the top-page copy's `frame.ready` and `options.status` are refused (`frameId` 0). The log records the frame page's `sender.url` origin in Chrome (static or dynamic id) for INT-11.12's Verify check |
| T78 INT-11.25 | E7-S7e: the Safari handler test; the first-connection frame, Larsal's dialog open | Cancel; then the test answerer allows in Larsal. Again with no answer | No hello is sent at Cancel; the popup closes; Larsal's dialog stays; after Allow the next popup shows the matches frame. With no answer: Larsal's dialog closes as Deny after 120 s and the next popup shows MI11-61 |
| T79 INT-11.31, INT-11.34 | The fill menu, then the new-password frame; Chrome headless, then Firefox 140 headless (E7-S7j) | A trusted click on "Search ‹vault›…", then on "Open the generator…" | `frame.popup` and `browser.action.openPopup()` run inside the click handler; the call resolves and the popup opens on its search, then on its Generator tab; with a test seam that makes the call reject, MI11-99 shows in one line and the frame stays open |
| T80 INT-11.25 | A new profile; the first-connection frame open, port route (Chrome); Larsal's dialog open (test answerer holds it) | Close the popup and open it again twice; then close it, and the test answerer denies in Larsal; then open the popup | Each reopened popup shows the first-connection frame; Larsal's request log has one `connect` only and Larsal queues no second dialog. After the Deny the next popup shows MI11-61 with Try Again and sends no `connect`; Try Again sends one |
| T81 INT-11.10 | Session on the port route, proven for V; V unlocked and shown in Larsal; the popup and the options page open | The test Larsal locks V, which sends a boxed `locked` notice (INT-01.46); then the test Larsal sends a box without `req` that opens but holds no `"type":"notice"` | The notice: both pages ask the background for the state again and the popup shows the locked frame; no request is answered by it. The other box is dropped without effect |
| T82 INT-11.20, INT-11.35 | A `site-a.test` sign-up form whose submit loads `https://sub.site-a.test/welcome`; no match; save on; test clock | Type a user name and password; submit. Again, and the welcome page moves on to `site-b.test`, then back to `site-a.test` within 150 s. Again, close the frame with a click outside, wait 151 s, then load another `site-a.test` page. Again, switch to another tab and back. Again, and close the tab. Again, with a test seam that makes the `frame.show` carry another origin. Again, and click Never for this site in the frame on the welcome page; then submit the `site-a.test` form once more. Then, with `never_save` cleared, a `site-a.test` form whose submit loads no new page: submit, and leave the save frame open. Then a change-password form on `site-a.test` (match `demo`): Use in the new-password frame, and a submit that loads a new page. Then, with a match `alex_m` on `site-a.test`, the sign-up form with another user name | The save frame shows on the welcome page, through a new token for its top frame and a `frame.show` that holds `https://sub.site-a.test`; its Title row reads `site-a.test (‹username›)`; Save sends one `logins.save` with the typed values and the form page's `url` and `form_url`. After `site-b.test`: no frame there or back on `site-a.test`, and the background holds no values. After 151 s: no frame, no values. After the tab switch: the frame shows again. After the tab closes: no values. Another origin: nothing shows. Never for this site: `never_save` holds `site-a.test`, not `sub.site-a.test`, and the next submit on `site-a.test` shows no frame. The form that loads no new page: at 151 s the frame closes (`frame.hide`), the background holds no values, and a `frame.save` with its token is refused. The change-password form: the update frame shows on the next page, and Update sends one `logins.update`. With the match `alex_m`: the frame on the welcome page shows MI11-56 with `site-a.test` and `alex_m` |
| T83 INT-11.44 | `public_suffix_list.dat` and the list project's `tests/test_psl.txt` (public domain, CC0) of the same version; the module in the background through the driver | Run each `checkPublicSuffix(input, expected)` line, with the input and the expected value turned to ASCII as INT-11.44 says; then `site-a.test`, `sub.site-a.test`, `127.0.0.1` and `localhost` | Every line gives its expected registrable domain (`null`: none; a null input or one with an empty label gives none); `site-a.test` and `sub.site-a.test` give `site-a.test`; `127.0.0.1` and `localhost` give none, so INT-11.20 compares their hosts |
| T84 INT-11.22 | `site-a.test` with one match; a search text with one result; then two of each | Open the popup; click in the user name field; type the search text | One: MI11-21 b (`site-a.test · 1 match`), MI11-48 b and MI11-41 b show. Two: MI11-21, MI11-48 and MI11-41 with 2 |
| T85 INT-11.26 | A paired profile (proven for V); V open and locked; S-BRW-10 off in Larsal's test settings | Open the popup; click Unlock in Larsal | `unlock` gets error 1 at once; the locked frame (MI11-15 with V's name) stays and shows MI11-103 with V's name in one line, not MI11-64; Larsal's log shows no unlock panel opened |
| T86 INT-11.23 | A paired profile; Larsal running with no vault open | Open the popup | MI11-64 in one line with Open Larsal (MI11-10); no pairing words and no MI11-13; Larsal's request log has `status` (an empty `vaults` list) and `check` (error 8), and no `connect` |
| T87 INT-11.22, INT-11.33 | The fill menu shown on `site-a.test` (match `demo` in V); S-BRW-10 off | The test Larsal locks V; a trusted click on the match | `logins.get` gets error 1; MI11-105 with V's name shows in one line in the menu; nothing fills |
| T88 INT-11.22, INT-11.33 | The fill menu shown on `site-a.test` (match `demo` in V) | The test Larsal answers the pick's `logins.get` with error 8 | MI11-99 shows in one line in the menu; nothing fills; the identification key stays |
| T89 INT-11.22, INT-11.33 | The fill menu shown on `site-a.test` (match `demo` in V) | The test host program answers the pick's `logins.get` with error 44 | MI11-01 shows in one line in the menu; nothing fills |

## How this was learned

- Public sources only. The reference app and its source were not opened for this card; the reference's own extension was not looked at.
- spec/research/browser-and-web.md sections 1 to 9 and the picks B1 to B12 (2026-10-31), with the sources it links: Chrome's native messaging, service worker lifecycle, content scripts, `web_accessible_resources`, "Stay secure", `activeTab`, browser namespace, manifest key and CSP pages; MDN's MessageSender, native manifests and background pages; Chromium's compromised-renderer threat model; Apple's Safari web extension messaging and app group pages; Mozilla's MV3 and signing pages; Bitwarden's public manifest and help pages; Princeton CITP (2017); Oesch and Ruoti (USENIX Security 2020, section 7.1); Marek Toth, "DOM-based Extension Clickjacking" (2025, updated 2026-01-14).
- Read 2026-11-01: W3C Web Cryptography API Level 2, editor's draft of 22 October 2026 (<https://w3c.github.io/webcrypto/>): X25519 "Derive Bits" (the all-zero check), "Generate Key" (the public key always extractable), "Import Key" (`raw` only for public keys, 256 bits), HKDF "Import key" (extractable must be false), "CryptoKey objects are serializable objects" and the IndexedDB note; MDN browser-compat-data at commit `0efedff8c8b6f131ad029443056bc74e00b1aca2` (the files named in "Minimum browser versions"); WebKit, "WebKit Features in Safari 18.4" (2025-03-31); Igalia, "Can I use Secure Curves in the Web Platform?" (2025-02-28, updated 2025-03-31); Mozilla Add-ons blog (2025-10-23); Chrome, "Manifest - Minimum Chrome Version" and "Manifest content_security_policy"; Chrome, `runtime` API, `MessageSender` (`tab` "present when the connection was opened from a tab", `frameId` "This will only be set when tab is set", <https://developer.chrome.com/docs/extensions/reference/api/runtime>); Chrome, `storage` API (`storage.local` `QUOTA_BYTES` 10,485,760, <https://developer.chrome.com/docs/extensions/reference/api/storage>); MDN, "User actions" ("Clicking a button on a page bundled with the extension", <https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/User_actions>); RFC 1035 section 2.3.4 (names of 255 octets or less); Chrome, "Localization message formats" (a message name holds only `A-Z`, `a-z`, `0-9`, `_` and `@`; names that begin with `@@` are reserved, <https://developer.chrome.com/docs/extensions/how-to/ui/localization-message-formats>); WHATWG HTML, "Focus" (the `activeElement` getter retargets against the node it is asked on; "when a child navigable is focused, its container is focused within its parent's active document", <https://html.spec.whatwg.org/multipage/interaction.html>); MDN, "web_accessible_resources" (Firefox's per-instance UUID); Bitwarden's public source at github.com/bitwarden/clients (`notification.background.ts`: one queued offer per tab, shown when the tab's `Utils.getDomain` equals the offer's, old offers of a tab removed before a new one, expired ones cleared every 30 s; `libs/common/src/autofill/constants/index.ts`: `NOTIFICATION_BAR_LIFESPAN_MS = 150000`; `libs/common/src/platform/misc/utils.ts`: `getDomain` through `tldts` `parse` with `allowPrivateDomains: true`, an IP address or `localhost` compared as its host); the Public Suffix List wiki, "Format" (the formal algorithm) and the list project's `tests/test_psl.txt` (CC0); Chrome, `tabs` API (host permissions give a tab's `url`; `onUpdated`, `onActivated`, `onRemoved`), `action` API (`setBadgeText` and `tabId`; "four or fewer characters") and `i18n` API (substitution strings); WAI-ARIA Authoring Practices, Combobox pattern (Escape); W3C WCAG 2.2, 2.5.3 Label in Name. The WHATWG HTML autofill tokens `username`, `current-password`, `new-password`, `one-time-code`.
- Project files: AGENTS.md; plan/epics.md E7; plan/architecture.md ("Browser extension and web vault (E7, E20)"); spec/decisions.md LD-162, LD-189, LD-191, LD-215, LD-272, LD-274; INT-01, INT-02, INT-04, FEA-03; `design/option-a/manifest.json` and `mockup.js` (the 15 extension frames' words and the options page's switch defaults); E7-S7b's `extension/test/driver.py` (its interface only).
