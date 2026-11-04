//! App's side of the browser bridge (E7; spec INT-01).
//!
//! E7-S1: the channel and its limits. [`Bridge`] holds the sessions: the
//! hello's X25519 key exchange and its two keys (app-crypto `bridge.rs`,
//! INT-01.49), boxed requests and replies with a nonce set per session,
//! the identification proof, and notices; it hands each opened request to
//! a [`Handler`] (the vault side, E7-S2 on). [`Server`] listens on one Unix
//! socket per [`Route`]: App's bridge socket behind `app-bridge`, where a
//! session belongs to its connection, and the Safari socket, where each
//! message may come on a new connection and a session is found by its
//! `sid` and ends after [`IDLE`] without a request (INT-01.14).
//!
//! Every failure is an error number of INT-01.40 inside the reply; no
//! reply, error or `Debug` output holds a key or a decrypted content.
//!
//! E7-S3: URL matching (INT-03). [`Page`] reads a page and ranks an entry
//! against it; [`order`] gives the offer order; [`registrable_domain`] is
//! App's own Public Suffix List matcher over the list compiled into the
//! build (INT-03.10, INT-03.19), for INT-02.19 and INT-04.11 too.
//!
//! E7-S2: the vault side (INT-02). [`VaultSide`] answers the requests
//! that read vaults over any [`Vaults`]: associations, which entries a
//! page may see, summaries without secrets, and secrets only after the
//! site access state allows them; its dialogs wait one at a time in
//! [`Prompts`]. [`Lists`] and [`State`] are an entry's site access.
//!
//! E7-S6: native messaging setup. [`Manifests`] writes and removes the
//! setup file each browser reads to start `app-bridge` (INT-01.8 to
//! INT-01.11); [`Listeners`] puts the two sockets where INT-01.6 and
//! INT-01.13 say and turns them on and off with S-BRW-01 and the Safari
//! switch, with the peer program check of signed builds (INT-01.7).
#![forbid(unsafe_code)]
// Rust rule 4: every message is hostile input. Test code is exempt via
// clippy.toml.
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]
#![deny(missing_docs)]

mod channel;
mod matching;
mod prompts;
mod psl;
mod server;
mod setup;
mod site;
mod vaults;

pub use channel::{
    Bridge, Handler, IDLE, Live, MAX_CONTENT, MAX_DEPTH, MAX_HELLOS, MAX_IN_FLIGHT, MAX_REQUESTS,
    MAX_SAFARI, MAX_TEXT, MAX_URL, MAX_VALUES, MAX_WAITING, Request, Route, SharedHandler, Step,
    Waiting, Work,
};
pub use matching::{
    MAX_ENTRY_URL, MAX_PATTERN_LABELS, MAX_STARS, MAX_URLS, NOT_A_PAGE, Note, Page, Site,
    extra_url_order, note, order,
};
pub use prompts::{
    Access, Answer, CONNECT_TIME, Connect, MAX_QUEUE, Outcome, PROMPT_TIME, Prompts, Question, Row,
};
pub use psl::{list_version, registrable_domain};
pub use server::{Clock, MAX_CONNECTIONS, MAX_FRAME, MAX_SOCKET_PATH, Program, Server, read_frame};
pub use setup::{
    ADDON_ID, BRIDGE_SOCKET, Browser, GROUP, HOST, Listeners, MI01_04, Manifests, RELAYS,
    SAFARI_SOCKET, STORE_IDS, Signature, Signed, Trouble, requirement,
};
pub use site::{
    Lists, MAX_NAME, MAX_SITES, MAX_USES, State, entry_id, iso, last_use, names, pairing_words,
    read_entry_id, record_use, valid_name, vault_id,
};
pub use vaults::{
    Changed, MAX_FOUND, MAX_IDS, MAX_RECENT, MAX_SEARCH, OpenVault, Options, VaultSide, Vaults,
};
