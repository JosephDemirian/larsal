//! The rollback guard's measures of one version of a vault (APP-05.26 for
//! the local file, SYN-03.7 for the server copy; LD-267 (3), LD-269 (4)):
//! the newest change time, and the KDF settings compared as MOD-11.19
//! limit 1 compares them. larsal-ffi's local state and larsal-sync's state keep
//! the same values, so both read them here.
//!
//! Guarantees: pure functions of public vault data; no key, password or
//! entry content goes in or out.

use larsal_model::json::{Map, Value};
use larsal_model::{Argon2Kind, FileVersion, Group, Kdf, Time, Vault};

/// The newest change time of `v`, stored as `version`: every entry's and
/// group's Mod and Loc, every deleted-object time and the metadata change
/// times (APP-05.26). A version 3 file stores no SettingsChanged and the
/// reader fills in the open time, so that time counts only for version 4
/// and later (LD-185, as MOD-11.19's merge; F-218).
#[must_use]
pub fn newest(v: &Vault, version: Option<FileVersion>) -> Time {
    fn walk(g: &Group, best: &mut Time) {
        for t in [&g.times]
            .into_iter()
            .chain(g.entries.iter().map(|e| &e.times))
        {
            *best = (*best).max(t.last_modification).max(t.location_changed);
        }
        for child in &g.groups {
            walk(child, best);
        }
    }
    let m = &v.meta;
    let mut best = [
        m.name_changed,
        m.description_changed,
        m.default_user_name_changed,
        m.master_key_changed,
        m.recycle_bin_changed,
        m.entry_templates_group_changed,
    ]
    .into_iter()
    .chain(
        version
            .is_none_or(|r| r.major >= 4)
            .then_some(m.settings_changed),
    )
    .chain(v.deleted_objects.iter().map(|d| d.deleted_at))
    .max()
    .unwrap_or(Time(i64::MIN));
    walk(&v.root, &mut best);
    best
}

/// `next` is lower than `stored` by MOD-11.19 limit 1: AES-KDF replacing
/// Argon2, less memory, fewer iterations or rounds.
#[must_use]
pub fn kdf_lower(stored: &Kdf, next: &Kdf) -> bool {
    match (stored, next) {
        (Kdf::AesKdf { rounds: a }, Kdf::AesKdf { rounds: b }) => b < a,
        (Kdf::Argon2 { .. }, Kdf::AesKdf { .. }) => true,
        (Kdf::AesKdf { .. }, Kdf::Argon2 { .. }) => false,
        (
            Kdf::Argon2 {
                iterations: ia,
                memory_kib: ma,
                ..
            },
            Kdf::Argon2 {
                iterations: ib,
                memory_kib: mb,
                ..
            },
        ) => ib < ia || mb < ma,
    }
}

fn kind_name(d: bool) -> &'static str {
    if d { "d" } else { "id" }
}

/// The KDF settings as the state files keep them: `{"aes":rounds}` or
/// `{"argon2":"d"|"id","i":…,"m":…,"p":…}`.
#[must_use]
pub fn kdf_json(k: &Kdf) -> Value {
    let mut m = Map::new();
    match k {
        Kdf::AesKdf { rounds } => {
            m.insert("aes".into(), (*rounds).into());
        }
        Kdf::Argon2 {
            kind,
            iterations,
            memory_kib,
            lanes,
        } => {
            m.insert("argon2".into(), kind_name(*kind == Argon2Kind::D).into());
            m.insert("i".into(), (*iterations).into());
            m.insert("m".into(), (*memory_kib).into());
            m.insert("p".into(), (*lanes).into());
        }
    }
    Value::Object(m)
}

/// [`kdf_json`]'s value read back; `None` for anything else, a key it does
/// not know included (F-241).
#[must_use]
pub fn kdf_of(v: &Value) -> Option<Kdf> {
    let map = v.as_object()?;
    let known = |keys: &[&str]| map.keys().all(|k| keys.contains(&k.as_str()));
    if let Some(rounds) = map.get("aes") {
        return known(&["aes"]).then_some(Kdf::AesKdf {
            rounds: rounds.as_u64()?,
        });
    }
    if !known(&["argon2", "i", "m", "p"]) {
        return None;
    }
    let number = |key: &str| map.get(key).and_then(Value::as_u64);
    Some(Kdf::Argon2 {
        kind: match map.get("argon2")?.as_str()? {
            "d" => Argon2Kind::D,
            "id" => Argon2Kind::Id,
            _ => return None,
        },
        iterations: number("i")?,
        memory_kib: number("m")?,
        lanes: number("p")?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The KDF settings round-trip; a value or a key that does not read is
    /// `None` (F-241).
    #[test]
    fn kdf_settings_round_trip_and_refuse_unknown_keys() {
        for k in [
            Kdf::AesKdf { rounds: 7 },
            Kdf::Argon2 {
                kind: Argon2Kind::D,
                iterations: 3,
                memory_kib: 1024,
                lanes: 1,
            },
            Kdf::Argon2 {
                kind: Argon2Kind::Id,
                iterations: 2,
                memory_kib: 65_536,
                lanes: 2,
            },
        ] {
            assert_eq!(kdf_of(&kdf_json(&k)), Some(k));
        }
        for bad in [
            r#"{"aes":7,"x":1}"#,
            r#"{"argon2":"id","i":2,"m":1024,"p":1,"q":1}"#,
            r#"{"argon2":"q","i":2,"m":1024,"p":1}"#,
            r#"{"argon2":"id","i":2,"m":1024}"#,
            r#"{"aes":"7"}"#,
            "5",
        ] {
            let v = larsal_model::json::from_str(bad).unwrap();
            assert_eq!(kdf_of(&v), None, "{bad}");
        }
    }
}
