//! Website icons on request (F-094; MOD-06.11, APP-01.21, SN-02, LD-64):
//! the selected entries' sites, asked only while S-ENTRY-11 is on, through
//! app-platform `net` (https, http only when the entry URL uses it, at most
//! 5 redirects, never from https to http). The addresses come from app-core
//! (`icons::download_addresses`): no user name, password, path, query or
//! fragment of the entry URL is sent. Every image is decoded in Rust and
//! re-encoded as PNG before the screen sees it (LD-65).

use crate::session::{AppError, Session};
use crate::views::{count, parse_id, plain_in};
use app_core::icons;
use std::collections::BTreeMap;
use std::time::{Duration, Instant};

/// What a download did, in plain words for the window's notice.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct IconFetch {
    /// How many entries got a downloaded icon.
    pub set: u32,
    /// "Fetched the site icon for N entries." or why nothing came.
    pub message: String,
}

/// Where icon bytes come from: app-platform `net` in the app, a fake in
/// tests. `None` when the address gives nothing within `budget`.
pub(crate) trait IconGet {
    fn get(&self, url: &str, budget: Duration) -> Option<Vec<u8>>;
}

/// The product transport: one client per address with the time left
/// (SN-01: making one opens no connection).
struct Net;

impl IconGet for Net {
    #[cfg(feature = "net")]
    fn get(&self, url: &str, budget: Duration) -> Option<Vec<u8>> {
        use app_platform::net::{Client, Timeouts};
        // The longest answer read: MOD-06's input limit.
        const MAX_BYTES: u64 = 16 << 20;
        let timeouts = Timeouts {
            connect: budget,
            read: budget,
            total: budget,
        };
        Client::new(timeouts).ok()?.get_icon(url, MAX_BYTES).ok()
    }

    #[cfg(not(feature = "net"))]
    fn get(&self, _: &str, _: Duration) -> Option<Vec<u8>> {
        None
    }
}

/// APP-01.21: the addresses in order until one gives an image that decodes,
/// all within `limit` (S-ENTRY-10); `None` when time runs out first.
fn first_icon(get: &dyn IconGet, addresses: &[String], limit: Duration) -> Option<Vec<u8>> {
    let start = Instant::now();
    addresses.iter().find_map(|url| {
        let left = limit
            .checked_sub(start.elapsed())
            .filter(|l| !l.is_zero())?;
        let data = get.get(url, left)?;
        icons::decode(&data, &icons::Images, &icons::Limits::DEFAULT).map(|_| data)
    })
}

impl Session {
    /// MOD-06.11's bulk download through `get`.
    pub(crate) fn fetch_icons_with(
        &self,
        vault: u64,
        entries: &[String],
        get: &dyn IconGet,
    ) -> Result<IconFetch, AppError> {
        if !self.settings.flag("icons.download".into()) {
            return Err(AppError::Refused(
                "Website icon downloads are off. Turn them on in Settings › Entries.".to_owned(),
            ));
        }
        let service = self.settings.flag("icons.use_service".into());
        let seconds = self
            .settings
            .number("icons.download_timeout".into())
            .clamp(1, 60);
        let limit = Duration::from_secs(seconds.unsigned_abs());
        // One download per site: the entries whose URLs give the same
        // addresses share it (MOD-06.11).
        let ids = entries
            .iter()
            .map(|id| parse_id(id, AppError::UnknownEntry))
            .collect::<Result<Vec<_>, _>>()?;
        let sites = self.with_vault(vault, |v| {
            let mut sites: BTreeMap<Vec<String>, Vec<app_model::Uuid>> = BTreeMap::new();
            for &id in &ids {
                let e = crate::views::find(&v.root, id, &mut Vec::new())
                    .ok_or(AppError::UnknownEntry)?;
                let addresses = icons::download_addresses(&plain_in(v, e, "URL"), service);
                if !addresses.is_empty() {
                    sites.entry(addresses).or_default().push(id);
                }
            }
            Ok(sites)
        })?;
        // The network runs without the session lock.
        let found: Vec<(Vec<app_model::Uuid>, Vec<u8>)> = sites
            .into_iter()
            .filter_map(|(addresses, ids)| Some((ids, first_icon(get, &addresses, limit)?)))
            .collect();
        let mut set = 0;
        for (ids, data) in found {
            set += self.change(vault, |v, now| {
                let icon = icons::apply_bulk_download(
                    v,
                    &ids,
                    &data,
                    &icons::Images,
                    &icons::Limits::DEFAULT,
                    now,
                )
                .map_err(|e| crate::edit::refused(&e))?;
                Ok(icon.map_or((0, Vec::new()), |_| (ids.len(), ids.clone())))
            })?;
        }
        Ok(IconFetch {
            set: count(set),
            message: match set {
                0 => "The site icon could not be fetched.".to_owned(),
                1 => "Fetched the site icon for 1 entry.".to_owned(),
                n => format!("Fetched the site icon for {n} entries."),
            },
        })
    }
}

#[uniffi::export]
impl Session {
    /// MOD-06.11, APP-01.21 (F-094): downloads the site icon of each entry
    /// in `entries` (32-digit ids) and sets it, one change per site. Only
    /// while S-ENTRY-11 is on; S-ENTRY-10 bounds each site's attempt. Uses
    /// the network: call it off the main thread, only on the user's press.
    /// No secret crosses; the answer is a count and a notice.
    ///
    /// # Errors
    /// `UnknownVault`, `Locked`, `UnknownEntry`; `Refused` while downloads
    /// are off, and in a build with no network code (SN-05, F-093).
    pub fn fetch_site_icons(
        &self,
        vault: u64,
        entries: Vec<String>,
    ) -> Result<IconFetch, AppError> {
        if !core_has_network() {
            return Err(AppError::Refused(NO_NETWORK.to_owned()));
        }
        self.fetch_icons_with(vault, &entries, &Net)
    }
}

/// SN-05 (F-093): the icon download's answer in a build with no network code.
const NO_NETWORK: &str = "This build of App has no network code, so it cannot fetch site icons.";

/// Takes nothing; false when this build of App has no network code (SN-05,
/// F-093: built without app-ffi's `net` feature), so the window shows that
/// in place of the online check and the icon download.
#[uniffi::export]
#[must_use]
pub fn core_has_network() -> bool {
    cfg!(feature = "net")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app_settings::AppSettingValue as V;
    use crate::edit::EditText;
    use std::sync::Mutex;

    /// A 1 × 1 PNG (base64), as tests/edit.rs.
    fn png() -> Vec<u8> {
        app_format::document::encode::base64_decode(
            "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAAAAYAAjCB0C8AAAAASUVORK5CYII=",
        )
    }

    /// The fake transport: answers `icon` for addresses on `host` and
    /// records every address asked; never reaches the network.
    struct Fake {
        host: &'static str,
        icon: Vec<u8>,
        asked: Mutex<Vec<String>>,
    }

    impl IconGet for Fake {
        fn get(&self, url: &str, _: Duration) -> Option<Vec<u8>> {
            self.asked.lock().unwrap().push(url.to_owned());
            url.contains(self.host).then(|| self.icon.clone())
        }
    }

    fn entry(s: &Session, v: u64, title: &str, url: &str) -> String {
        s.begin_new(v, None).unwrap();
        s.set_text(v, EditText::Title, title.into()).unwrap();
        s.set_text(v, EditText::Url, url.into()).unwrap();
        s.commit_edit(v).unwrap()
    }

    /// F-094 (SN-02, MOD-06.11): off by default; once on, the selected
    /// entries' sites are asked without the URL's user name, password,
    /// path, query or fragment, and the icon is set on every entry of the
    /// site as one change.
    #[test]
    fn f_094_icons_download_on_request_only() {
        let path = crate::test_dir::TempDir::new("icons").file("Personal.appvault");
        std::fs::copy(
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../testdata/option-a-personal.appvault"
            ),
            &path,
        )
        .unwrap();
        let s = Session::new();
        let v = s.open(path.to_string_lossy().into_owned()).unwrap();
        s.unlock(v, Some("demo-pass-7".into()), None).unwrap();
        let a = entry(&s, v, "A", "https://alice:pw@login.example.com/acct?q=1#x");
        let b = entry(&s, v, "B", "https://login.example.com/other");
        let c = entry(&s, v, "C", "https://nothing.example.org/");
        let fake = Fake {
            host: "login.example.com",
            icon: png(),
            asked: Mutex::new(Vec::new()),
        };
        let all = [a.clone(), b.clone(), c.clone()];
        // S-ENTRY-11 is off: nothing is asked.
        let off = s.fetch_icons_with(v, &all, &fake);
        assert!(matches!(off, Err(AppError::Refused(_))), "{off:?}");
        assert!(fake.asked.lock().unwrap().is_empty());
        s.save_settings(vec![crate::app_settings::AppSetting {
            key: "icons.download".to_owned(),
            value: V::Flag { on: true },
        }])
        .unwrap();
        let before = s.save_status(v).unwrap().changes;
        let got = s.fetch_icons_with(v, &all, &fake).unwrap();
        assert_eq!(got.set, 2, "{got:?}");
        assert_eq!(got.message, "Fetched the site icon for 2 entries.");
        let asked = fake.asked.lock().unwrap().clone();
        assert_eq!(
            asked,
            [
                "https://login.example.com/favicon.ico",
                "https://nothing.example.org/favicon.ico",
                "https://example.org/favicon.ico",
            ]
        );
        assert!(
            asked
                .iter()
                .all(|u| !u.contains("alice") && !u.contains("acct"))
        );
        // One change for the one site that answered.
        assert_eq!(s.save_status(v).unwrap().changes, before + 1);
        let custom =
            |id: &str| s.with_vault(v, |vault| Ok(crate::views::entry_of(vault, id)?.icon));
        assert!(matches!(custom(&a).unwrap(), app_model::Icon::Custom(_)));
        assert_eq!(custom(&a).unwrap(), custom(&b).unwrap());
        assert!(matches!(custom(&c).unwrap(), app_model::Icon::Standard(_)));
    }

    /// F-093 (SN-05): a build with no network code says so, before any
    /// setting, vault or entry is looked at; a build with it never does.
    #[test]
    fn f_093_no_network_build_says_so() {
        // The oracle is the build's own feature, not the function under test.
        let net = cfg!(feature = "net");
        assert_eq!(core_has_network(), net);
        let got = Session::new().fetch_site_icons(0, Vec::new());
        let says = matches!(&got, Err(AppError::Refused(m)) if m == NO_NETWORK);
        assert_eq!(says, !net, "{got:?}");
    }

    /// APP-01.21: one time limit for the whole attempt.
    #[test]
    fn f_094_time_limit_covers_every_address() {
        struct Slow(Mutex<u32>);
        impl IconGet for Slow {
            fn get(&self, _: &str, budget: Duration) -> Option<Vec<u8>> {
                *self.0.lock().unwrap() += 1;
                std::thread::sleep(budget.min(Duration::from_millis(30)));
                None
            }
        }
        let slow = Slow(Mutex::new(0));
        let many: Vec<String> = (0..100).map(|n| format!("https://h{n}.example/")).collect();
        assert!(first_icon(&slow, &many, Duration::from_millis(100)).is_none());
        assert!(*slow.0.lock().unwrap() < 10);
    }
}
