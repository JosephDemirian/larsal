//! The commands C01 to C26 (INT-10.21 to INT-10.44). Each checks its options
//! and arguments before any password is read (INT-10.5), then unlocks (or
//! takes the shell's open vault), runs, and saves once at its end.

use crate::args::{self, Parsed};
use crate::term::{self, Res, fail};
use crate::vault::{self, Creds, Session, Unlock, find_entry, find_group, now};
use crate::zone::{self, Local};
use larsal_core::generator::{passphrase, password, wordlist};
use larsal_core::health::{self, Ratings};
use larsal_core::time::Instant;
use larsal_core::{
    attachments, breach, edit, export, import, merge, recycle, refs, search, settings, stats,
    storage, totp,
};
use larsal_crypto::secret::{SecretString, ct_eq};
use larsal_format::Saved;
use larsal_format::limits::Limits;
use larsal_model::{Entry, Field, Group, Kdf, MemoryProtection, Switch, Uuid, Vault};
use std::time::Duration;

/// Runs one command. `open`: the shell's vault, if one is open.
pub fn run(p: &Parsed, open: &mut Option<Session>) -> Res {
    match p.cmd.name {
        "add" => add(p, open),
        "analyze" => analyze(p, open),
        "attachment-export" => attachment_export(p, open),
        "attachment-import" => attachment_import(p, open),
        "attachment-rm" => attachment_rm(p, open),
        "clip" => clip(p, open),
        "db-create" => db_create(p),
        "db-edit" => db_edit(p, open),
        "db-info" => db_info(p, open),
        "passphrase" => passphrase_cmd(p),
        "edit" => edit_cmd(p, open),
        "estimate" => estimate(p),
        "export" => export_cmd(p, open),
        "generate" => generate(p),
        "help" => {
            let text = match p.arg(0).and_then(|c| args::lookup(c, open.is_some())) {
                Some(c) => args::command_help(c),
                None => args::overview(),
            };
            print!("{text}");
            Ok(())
        }
        "import" => import_cmd(p),
        "ls" => ls(p, open),
        "merge" => merge_cmd(p, open),
        "mkdir" => mkdir(p, open),
        "mv" => mv(p, open),
        "rm" => rm(p, open),
        "rmdir" => rmdir(p, open),
        "search" => search_cmd(p, open),
        "show" => show(p, open),
        // close outside the shell does nothing (INT-10.44).
        _ => Ok(()),
    }
}

/// The arguments after VAULT (the shell's open vault takes its place).
fn rest<'p>(p: &'p Parsed, open: &Option<Session>) -> Vec<&'p str> {
    let skip = usize::from(open.is_none() && p.cmd.unlocks());
    p.args.iter().skip(skip).map(String::as_str).collect()
}

/// The open vault, or VAULT unlocked for this command.
fn session<'a>(
    p: &Parsed,
    open: &'a mut Option<Session>,
    own: &'a mut Option<Session>,
) -> Res<&'a mut Session> {
    if let Some(s) = open {
        return Ok(s);
    }
    let path = p.arg(0).unwrap_or("");
    Ok(own.insert(vault::unlock(path, &Unlock::of(p))?))
}

/// A success line; none with `-q` (INT-10.7).
fn done(p: &Parsed, line: &str) {
    if !p.quiet() {
        term::out(line);
    }
}

fn core(e: larsal_core::Error) -> term::Fail {
    fail(format!("{e}."))
}

fn no_entry(path: &str) -> term::Fail {
    fail(format!("no entry at {path}."))
}

fn no_group(path: &str) -> term::Fail {
    fail(format!("no group at {path}."))
}

fn entry_id(v: &Vault, path: &str) -> Res<Uuid> {
    find_entry(v, path)
        .map(|(e, _)| e.uuid)
        .ok_or_else(|| no_entry(path))
}

fn group_id(v: &Vault, path: &str) -> Res<Uuid> {
    find_group(v, path)
        .map(|g| g.uuid)
        .ok_or_else(|| no_group(path))
}

fn entry(v: &Vault, id: Uuid) -> Option<&Entry> {
    v.root.all_entries().find(|e| e.uuid == id)
}

// ---------------------------------------------------------------------------
// Generator options (FEA-02.21) and entry fields.

/// The generator options of G, checked (M10-32).
fn generator(p: &Parsed) -> Res<password::Options> {
    use password::{Class, Invalid};
    let length = match p.value("length") {
        Some(v) => v
            .parse::<u32>()
            .map_err(|_| fail(format!("{v} is not a usable length.")))?,
        None => 32,
    };
    let mut classes = Vec::new();
    for (flag, add) in [
        ("lower", &[Class::Lower][..]),
        ("upper", &[Class::Upper]),
        ("numeric", &[Class::Digits]),
        (
            "special",
            &[
                Class::Brackets,
                Class::Punctuation,
                Class::Quotes,
                Class::Dashes,
                Class::Math,
                Class::Signs,
            ],
        ),
        ("extended", &[Class::Extended]),
    ] {
        if p.flag(flag) {
            classes.extend_from_slice(add);
        }
    }
    let o = password::Options::command_line(
        length,
        &classes,
        p.value("custom"),
        p.value("exclude").unwrap_or(""),
        p.flag("exclude-similar"),
        p.flag("every-group"),
    );
    let why = match password::groups(&o) {
        Ok(_) => return Ok(o),
        Err(Invalid::LengthOutOfRange) => {
            let v = p.value("length").unwrap_or("32");
            return Err(fail(format!("{v} is not a usable length.")));
        }
        Err(Invalid::TextTooLong) => {
            "the custom or excluded characters are more than 1024".to_owned()
        }
        Err(Invalid::NoCharacters) => "no character is left to choose from".to_owned(),
        Err(Invalid::TooShortForEveryGroup(n)) => {
            format!("a character from every group needs a length of at least {n}")
        }
    };
    Err(fail(format!(
        "these generator options cannot make a password: {why}."
    )))
}

fn generated(o: &password::Options) -> Res<SecretString> {
    password::generate(o).map_err(|_| fail("could not get random numbers from macOS."))
}

/// add and edit: `-g` with `-p` (M10-31), then the generator (M10-32).
fn password_source(p: &Parsed) -> Res<Option<password::Options>> {
    if p.flag("generate") && p.flag("password-prompt") {
        return Err(fail("--generate and --password-prompt exclude each other."));
    }
    if p.flag("generate") {
        return generator(p).map(Some);
    }
    Ok(None)
}

/// The entry password of add or edit: read (`-p`) or made (`-g`).
fn entry_password(
    p: &Parsed,
    maker: Option<&password::Options>,
    prompt: &str,
) -> Res<Option<SecretString>> {
    if p.flag("password-prompt") {
        return Ok(Some(term::read_secret(prompt, p.quiet())));
    }
    maker.map(generated).transpose()
}

/// Sets field `name`, keeping its protection flag, or the vault's for a new one.
fn set(e: &mut Entry, v_protect: bool, name: &str, value: SecretString) {
    let protected = e.field(name).map_or(v_protect, |f| f.protected);
    e.set_field(name.to_owned(), Field { value, protected });
}

/// INT-10.21: `--username`, `--url`, `--notes` (with `\n` as a line end) and
/// `--title` when not empty, and the password.
fn fill(e: &mut Entry, mp: &MemoryProtection, p: &Parsed, pw: Option<SecretString>) {
    for (opt, name) in [
        ("title", "Title"),
        ("username", "UserName"),
        ("url", "URL"),
        ("notes", "Notes"),
    ] {
        if let Some(text) = p.text(opt) {
            let text = if name == "Notes" {
                text.replace("\\n", "\n")
            } else {
                text.to_owned()
            };
            set(e, mp.for_field(name), name, SecretString::new(text));
        }
    }
    if let Some(pw) = pw {
        set(e, mp.for_field("Password"), "Password", pw);
    }
}

// ---------------------------------------------------------------------------
// C01 add, C12 edit.

fn add(p: &Parsed, open: &mut Option<Session>) -> Res {
    let path = rest(p, open)[0];
    if path.is_empty() || path.ends_with('/') {
        return Err(fail(format!("{path} gives no title for the new entry.")));
    }
    let maker = password_source(p)?;
    let mut own = None;
    let s = session(p, open, &mut own)?;
    if find_entry(&s.vault, path).is_some() {
        return Err(fail(format!(
            "an entry is already found at {path}. To add one in the root group, start the path with /."
        )));
    }
    let (group, title) = path.rsplit_once('/').unwrap_or(("", path));
    let gid = group_id(&s.vault, group)?;
    let pw = entry_password(p, maker.as_ref(), "Entry password: ")?;
    let mut e = edit::new_entry(&s.vault, gid, false).map_err(core)?;
    // MOD-01.22: no default user name from the command line.
    e.set_field("UserName".into(), Field::empty());
    let protect = s.vault.meta.memory_protection.for_field("Title");
    set(
        &mut e,
        protect,
        "Title",
        SecretString::new(title.to_owned()),
    );
    fill(&mut e, &s.vault.meta.memory_protection, p, pw);
    edit::add_entry(&mut s.vault, gid, e, now()).map_err(core)?;
    s.save()?;
    let title = if protect { health::MASKED_TITLE } else { title };
    done(p, &format!("New entry {title} saved."));
    Ok(())
}

fn edit_cmd(p: &Parsed, open: &mut Option<Session>) -> Res {
    let path = rest(p, open)[0];
    let maker = password_source(p)?;
    let fields = ["title", "username", "url", "notes"];
    if maker.is_none() && !p.flag("password-prompt") && fields.iter().all(|f| p.text(f).is_none()) {
        return Err(fail(format!(
            "nothing to change in {path}. Give --title, --username, --url, --notes, --password-prompt or --generate."
        )));
    }
    let mut own = None;
    let s = session(p, open, &mut own)?;
    let id = entry_id(&s.vault, path)?;
    let pw = entry_password(p, maker.as_ref(), "New entry password: ")?;
    let mp = s.vault.meta.memory_protection.clone();
    edit::edit_entry(&mut s.vault, id, now(), |d| fill(d, &mp, p, pw)).map_err(core)?;
    let title = entry(&s.vault, id).map_or(String::new(), |e| vault::title(&s.vault, e).to_owned());
    s.save()?;
    done(p, &format!("Changes to {title} saved."));
    Ok(())
}

// ---------------------------------------------------------------------------
// C18 ls, C26 show, C25 search, C10 db-info.

fn ls(p: &Parsed, open: &mut Option<Session>) -> Res {
    let group = rest(p, open).first().copied().unwrap_or("");
    let mut own = None;
    let s = session(p, open, &mut own)?;
    let g = find_group(&s.vault, group).ok_or_else(|| no_group(group))?;
    let mut lines = Vec::new();
    let mask = s.vault.meta.memory_protection.for_field("Title");
    list(
        g,
        mask,
        0,
        "",
        p.flag("recursive"),
        p.flag("flatten"),
        &mut lines,
    );
    for l in lines {
        term::out(&l);
    }
    Ok(())
}

/// INT-10.27: titles in stored order (masked when protected, F-066; `mask`
/// is the vault's flag), then `<name>/` per child group.
fn list(
    g: &Group,
    mask: bool,
    depth: usize,
    prefix: &str,
    deep: bool,
    flat: bool,
    out: &mut Vec<String>,
) {
    let lead = if flat {
        prefix.to_owned()
    } else {
        "  ".repeat(depth)
    };
    if g.entries.is_empty() && g.groups.is_empty() {
        out.push(format!("{lead}(empty group)"));
        return;
    }
    for e in &g.entries {
        out.push(format!("{lead}{}", health::shown_title(e, mask)));
    }
    for c in &g.groups {
        out.push(format!("{lead}{}/", c.name));
        if deep {
            list(
                c,
                mask,
                depth + 1,
                &format!("{prefix}{}/", c.name),
                deep,
                flat,
                out,
            );
        }
    }
}

/// `{00000000-0000-0000-0000-00000000000a}`.
fn uuid_text(id: Uuid) -> String {
    let h: String = id.0.iter().map(|b| format!("{b:02x}")).collect();
    format!(
        "{{{}-{}-{}-{}-{}}}",
        &h[0..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..32]
    )
}

/// The field `name` asks for (INT-10.28): exact, else ignoring case;
/// `Uuid` and `Tags` exact only. M10-63, M10-64.
enum Pick<'e> {
    Uuid,
    Tags,
    Field(&'e str, &'e Field),
}

fn pick<'e>(e: &'e Entry, path: &str, name: &str) -> Res<Pick<'e>> {
    match name {
        "Uuid" => return Ok(Pick::Uuid),
        "Tags" => return Ok(Pick::Tags),
        _ => {}
    }
    if let Some((n, f)) = e.fields().find(|(n, _)| *n == name) {
        return Ok(Pick::Field(n, f));
    }
    let low = name.to_lowercase();
    let near: Vec<(&str, &Field)> = e
        .fields()
        .filter(|(n, _)| n.to_lowercase() == low)
        .collect();
    match near.as_slice() {
        [] => Err(fail(format!("{path} has no field called {name}."))),
        [(n, f)] => Ok(Pick::Field(n, f)),
        many => {
            let list: Vec<&str> = many.iter().map(|(n, _)| *n).collect();
            Err(fail(format!(
                "{name} could mean any of {}. Give the exact name.",
                list.join(", ")
            )))
        }
    }
}

/// Bytes as INT-10.28 shows them: under 1,024 `<n> B`, else KiB, MiB or GiB
/// with one decimal.
fn size_text(n: u64) -> String {
    const UNITS: [&str; 3] = ["KiB", "MiB", "GiB"];
    if n < 1024 {
        return format!("{n} B");
    }
    let mut unit = 1024u64;
    let mut i = 0;
    while i < 2 && n >= unit * 1024 {
        unit *= 1024;
        i += 1;
    }
    let tenths = (n * 10 + unit / 2) / unit;
    format!("{}.{} {}", tenths / 10, tenths % 10, UNITS[i])
}

fn show(p: &Parsed, open: &mut Option<Session>) -> Res {
    let path = rest(p, open)[0];
    let mut own = None;
    let s = session(p, open, &mut own)?;
    let (e, _) = find_entry(&s.vault, path).ok_or_else(|| no_entry(path))?;
    let t = now();
    let local = Local;
    let code = if p.flag("totp") {
        Some(
            totp::code_for(e, t)
                .ok_or_else(|| fail(format!("{path} has no one-time password.")))?,
        )
    } else {
        None
    };
    let reveal = p.flag("show-protected");
    let ctx = |display: bool| refs::Context {
        zone: &local,
        otp: totp::code_for,
        display,
        ..refs::Context::new(Some(&s.vault), t)
    };
    let (masked, full) = (ctx(!reveal), ctx(false));
    // R10-2: without -s, parts that resolve from a protected value print as
    // (hidden). ponytail: a literal `******` in a value prints as (hidden) too.
    let shown = |f: &Field| -> SecretString {
        if f.protected && !reveal {
            return SecretString::new("(hidden)".into());
        }
        let r = refs::resolve(f.value.expose(), e, &masked).text;
        if reveal || !r.expose().contains(refs::MASK) {
            r
        } else {
            SecretString::new(r.expose().replace(refs::MASK, "(hidden)"))
        }
    };
    let names = p.values("attributes");
    let all = p.flag("all");
    if all || (names.is_empty() && code.is_none()) {
        for n in ["Title", "UserName", "Password", "URL", "Notes"] {
            let value = e
                .field(n)
                .map_or_else(|| SecretString::new(String::new()), shown);
            term::out_pair(&format!("{n}: "), value.expose());
        }
        term::out(&format!("Uuid: {}", uuid_text(e.uuid)));
        term::out(&format!("Tags: {}", e.tags().join(",")));
    }
    if all {
        for (n, f) in e
            .fields()
            .filter(|(n, _)| !larsal_model::entry::STANDARD_FIELDS.contains(n))
        {
            term::out_pair(&format!("{n}: "), shown(f).expose());
        }
    }
    let mut ok = true;
    for name in names {
        match pick(e, path, name) {
            Ok(Pick::Uuid) => term::out(&uuid_text(e.uuid)),
            Ok(Pick::Tags) => term::out(&e.tags().join(",")),
            Ok(Pick::Field(_, f)) => {
                term::out_pair("", refs::resolve(f.value.expose(), e, &full).text.expose());
            }
            Err(_) => ok = false,
        }
    }
    if p.flag("show-attachments") {
        term::out("");
        let list = attachments::sorted(e);
        if list.is_empty() {
            term::out("No attached files.");
        } else {
            term::out("Attached files:");
            for a in list {
                let size = u64::try_from(a.data.len()).unwrap_or(u64::MAX);
                term::out(&format!("  {} ({})", a.name, size_text(size)));
            }
        }
    }
    if let Some(code) = code {
        term::out_pair("", code.expose());
    }
    if ok { Ok(()) } else { Err(term::Fail) }
}

/// A copy of the vault for the command line's search: every group's search
/// flag on (D-INT10-11); the walk itself skips the bin (LD-57).
fn searchable(v: &Vault) -> Vault {
    fn on(g: &mut Group) {
        g.searching = Switch::On;
        g.groups.iter_mut().for_each(on);
    }
    let mut copy = v.duplicate();
    on(&mut copy.root);
    copy
}

/// INT-10.30: the ids and paths of the entries `query` finds, in FEA-01's
/// order; a path names a protected Title with the mask (F-066), so take
/// the entry by its id. For `is:weak` every password is rated first, so the run's work bound is
/// not spent on rating (LD-185); a run still cut short, or an invalid
/// pattern, prints a note (FEA-01.31; not with `-q`).
fn find_paths(v: &Vault, query: &str, quiet: bool) -> Res<Vec<(Uuid, String)>> {
    let local = Local;
    let ratings = Ratings::new(&health::zxcvbn_bits);
    let copy = searchable(v);
    if search::rates(query) {
        ratings.fill(&copy);
    }
    let o = search::Options {
        zone: &local,
        ratings: Some(&ratings),
        ..search::Options::new(now())
    };
    let found = search::search(&copy, query, &o).map_err(|e| {
        fail(match e {
            search::QueryError::TooLong => "the search is longer than 1024 characters.",
            search::QueryError::TooManyTerms => "the search has more than 16 pattern terms.",
        })
    })?;
    if found.invalid && !quiet {
        term::err(if found.spent >= search::RUN_BUDGET {
            "Note: the search reached its work limit, so the list may be incomplete."
        } else {
            "Note: a pattern in this search is not valid or is too large, so it matched nothing."
        });
    }
    Ok(found
        .ids
        .iter()
        .filter_map(|&id| Some((id, vault::entry_path(v, id)?)))
        .collect())
}

fn search_cmd(p: &Parsed, open: &mut Option<Session>) -> Res {
    let term_text = rest(p, open)[0];
    let mut own = None;
    let s = session(p, open, &mut own)?;
    let paths = find_paths(&s.vault, term_text, p.quiet())?;
    if paths.is_empty() {
        return Err(fail(format!("no entry matches {term_text}.")));
    }
    for (_, path) in paths {
        term::out(&path);
    }
    Ok(())
}

fn db_info(p: &Parsed, open: &mut Option<Session>) -> Res {
    let mut own = None;
    let s = session(p, open, &mut own)?;
    let local = Local;
    let ratings = Ratings::new(&health::zxcvbn_bits);
    let modified = std::fs::metadata(&s.path)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|m| m.duration_since(std::time::UNIX_EPOCH).ok())
        .and_then(|d| larsal_model::Time::from_unix(i64::try_from(d.as_secs()).ok()?));
    let file = stats::FileInfo {
        path: Some(&s.path),
        modified,
        unsaved: false,
    };
    let st = stats::statistics(&ratings, &s.vault, &file, Instant::from(now()), &local);
    let enc = s.vault.encryption;
    let cipher = match enc.cipher {
        larsal_model::Cipher::Aes256 => "AES-256",
        larsal_model::Cipher::ChaCha20 => "ChaCha20",
        larsal_model::Cipher::Twofish256 => "Twofish",
    };
    let plural = |n: u64, one: &str| {
        if n == 1 {
            format!("1 {one}")
        } else {
            format!("{n} {one}s")
        }
    };
    let kdf = match enc.kdf {
        Kdf::AesKdf { rounds } => format!("AES-KDF, {}", plural(rounds, "round")),
        Kdf::Argon2 {
            kind,
            iterations,
            memory_kib,
            lanes,
        } => {
            let memory = if memory_kib % 1024 == 0 {
                format!("{} MiB", memory_kib / 1024)
            } else {
                format!("{memory_kib} KiB")
            };
            let name = match kind {
                larsal_model::Argon2Kind::Id => "Argon2id",
                larsal_model::Argon2Kind::D => "Argon2d",
            };
            format!(
                "{name}, {memory}, {}, {}",
                plural(iterations, "iteration"),
                plural(lanes, "lane")
            )
        }
    };
    let saved = modified.map_or_else(|| "unknown".to_owned(), |t| zone::rfc3339(t, &local));
    let lines = [
        ("Name", st.name.clone()),
        ("Description", st.description.clone()),
        ("Cipher", cipher.to_owned()),
        ("Key derivation", kdf),
        (
            "Recycle bin",
            if s.vault.meta.recycle_bin_enabled {
                "on"
            } else {
                "off"
            }
            .to_owned(),
        ),
        ("File", s.path.clone()),
        ("Created on", zone::rfc3339(st.created, &local)),
        ("Most recent save", saved),
        ("Changes not saved yet", "no".to_owned()),
        ("Groups", st.groups.to_string()),
        ("Entries", st.entries.to_string()),
        ("Past expiry", st.expired.to_string()),
        ("Different passwords", st.unique_pw.to_string()),
        ("Repeated passwords", st.reused_pw.to_string()),
        ("Most uses of one password", st.max_reuse.to_string()),
        ("Under 8 characters", st.short_pw.to_string()),
        ("Rated below Good", st.weak_pw.to_string()),
        ("Skipped in reports", st.excluded.to_string()),
        ("Length on average", st.avg_text()),
        ("Passkey entries", st.passkeys.to_string()),
        ("One-time code entries", st.totp.to_string()),
    ];
    for (label, value) in lines {
        term::out(&format!("{label}: {value}"));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// C06 clip (SC-07).

/// The pasteboard: the general one, or in a debug build started with
/// `LARSAL_TEST_PASTEBOARD` a private named one (AGENTS.md rule 10). Release
/// builds read no environment variable for it.
fn clipboard() -> larsal_platform::clipboard::Clipboard {
    #[cfg(debug_assertions)]
    if std::env::var_os("LARSAL_TEST_PASTEBOARD").is_some() {
        return larsal_platform::clipboard::Clipboard::private();
    }
    larsal_platform::clipboard::Clipboard::general()
}

fn clip(p: &Parsed, open: &mut Option<Session>) -> Res {
    let a = rest(p, open);
    let (given, secs) = (a[0], a.get(1).copied());
    let seconds = match secs {
        None => 10,
        Some(v) => v
            .parse::<u32>()
            .ok()
            .filter(|n| i32::try_from(*n).is_ok())
            .ok_or_else(|| fail(format!("{v} is not a number of seconds (0 or more).")))?,
    };
    if p.value("attribute").is_some() && p.flag("totp") {
        return Err(fail("--attribute and --totp exclude each other."));
    }
    let mut own = None;
    let s = session(p, open, &mut own)?;
    let mut path = given.to_owned();
    let mut picked = None;
    if p.flag("best-match") {
        let found = find_paths(&s.vault, &format!("title:{given}"), p.quiet())?;
        match found.as_slice() {
            [] => {}
            [(id, one)] => {
                done(p, &format!("Best match: {one}."));
                path.clone_from(one);
                picked = Some(*id);
            }
            many => {
                term::err(&format!("larsal: {} entries match {given}:", many.len()));
                for (_, m) in many {
                    term::err(m);
                }
                return Err(term::Fail);
            }
        }
    }
    // F-066: a best match is taken by its id; its path may be masked.
    let e = match picked {
        Some(id) => entry(&s.vault, id),
        None => find_entry(&s.vault, &path).map(|(e, _)| e),
    }
    .ok_or_else(|| no_entry(&path))?;
    let name = p.value("attribute").unwrap_or("Password");
    let otp = p.flag("totp") || name == "totp";
    let (label, value) = if otp {
        let code = totp::code_for(e, now())
            .ok_or_else(|| fail(format!("{path} has no one-time password.")))?;
        ("totp".to_owned(), code)
    } else {
        match pick(e, &path, name)? {
            Pick::Uuid => ("Uuid".to_owned(), SecretString::new(uuid_text(e.uuid))),
            Pick::Tags => ("Tags".to_owned(), SecretString::new(e.tags().join(","))),
            Pick::Field(n, f) => (n.to_owned(), SecretString::new(f.value.expose().to_owned())),
        }
    };
    // An empty value copies nothing and leaves the clipboard as it was
    // (APP-03.5, INT-10.29, LD-200 (8)).
    if value.expose().is_empty() {
        return Err(fail(format!(
            "{label} of {path} is empty. Nothing to copy."
        )));
    }
    // LD-178 (7): the vault this command unlocked is dropped (wiped) before
    // the wait; a shell's open vault stays open (INT-10.47).
    drop(own);
    // SC-07: from before the copy, a quit signal only cuts the wait short;
    // the clear below runs, then the guard's drop ends the process by it.
    let guard = larsal_platform::macos::catch_quit().ok();
    let board = clipboard();
    board
        .copy(value.expose(), None)
        .map_err(|_| fail("could not put the value on the clipboard."))?;
    drop(value);
    if seconds == 0 {
        done(
            p,
            &format!("{label} of {path} copied. The clipboard is not emptied."),
        );
        return Ok(());
    }
    done(
        p,
        &format!("{label} of {path} copied. The clipboard is emptied in {seconds} seconds."),
    );
    let countdown = term::stderr_tty() && !p.quiet();
    for left in (1..=seconds).rev() {
        if countdown {
            term::err_raw(&format!(
                "\r{left} s left before the clipboard is emptied\x1b[K"
            ));
        }
        let second = Duration::from_secs(1);
        let signal = match &guard {
            Some(g) => g.wait(second),
            None => {
                std::thread::sleep(second);
                None
            }
        };
        if signal.is_some() {
            board.clear();
            if countdown {
                term::err_raw("\r\x1b[K");
            }
            drop(guard); // restores the signal actions and raises it
            return Err(term::Fail);
        }
    }
    if countdown {
        term::err_raw("\r\x1b[K");
    }
    let emptied = board.clear();
    drop(guard);
    done(
        p,
        if emptied {
            "The clipboard is empty again."
        } else {
            "The clipboard holds something else now and was left as it is."
        },
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// C20 mkdir, C21 mv, C23 rm, C24 rmdir.

fn mkdir(p: &Parsed, open: &mut Option<Session>) -> Res {
    let path = rest(p, open)[0];
    let trimmed = path.strip_suffix('/').unwrap_or(path);
    let (parent, name) = trimmed.rsplit_once('/').unwrap_or(("", trimmed));
    let mut own = None;
    let s = session(p, open, &mut own)?;
    if find_group(&s.vault, trimmed).is_some() {
        return Err(fail(format!("a group {path} is already there.")));
    }
    let pid = group_id(&s.vault, parent)?;
    let mut g = edit::new_group(&s.vault).map_err(core)?;
    name.clone_into(&mut g.name);
    edit::add_group(&mut s.vault, pid, g, now()).map_err(core)?;
    s.save()?;
    done(p, &format!("New group {name} saved."));
    Ok(())
}

fn mv(p: &Parsed, open: &mut Option<Session>) -> Res {
    let a = rest(p, open);
    let (path, group) = (a[0], a[1]);
    let mut own = None;
    let s = session(p, open, &mut own)?;
    let (e, from) = find_entry(&s.vault, path).ok_or_else(|| no_entry(path))?;
    let (id, from, title) = (e.uuid, from.uuid, vault::title(&s.vault, e).to_owned());
    let to = find_group(&s.vault, group).ok_or_else(|| no_group(group))?;
    let (tid, gname) = (to.uuid, to.name.clone());
    if tid == from {
        return Err(fail(format!("nothing to move: {title} is in {gname}.")));
    }
    edit::move_entries(&mut s.vault, &[id], tid, now()).map_err(core)?;
    s.save()?;
    done(p, &format!("{title} moved to {gname}."));
    Ok(())
}

fn rm(p: &Parsed, open: &mut Option<Session>) -> Res {
    let path = rest(p, open)[0];
    let mut own = None;
    let s = session(p, open, &mut own)?;
    let id = entry_id(&s.vault, path)?;
    let title = entry(&s.vault, id).map_or(String::new(), |e| vault::title(&s.vault, e).to_owned());
    let d = recycle::delete_entries(&mut s.vault, &[id], now(), |_, _| {
        recycle::References::Delete
    })
    .map_err(core)?;
    s.save()?;
    if d.to_bin > 0 {
        done(p, &format!("{title} moved to the recycle bin."));
    } else {
        done(p, &format!("{title} deleted for good."));
    }
    Ok(())
}

fn rmdir(p: &Parsed, open: &mut Option<Session>) -> Res {
    let path = rest(p, open)[0];
    let trimmed = path.trim_start_matches('/').trim_end_matches('/');
    if trimmed.is_empty() {
        return Err(fail(
            "the root group belongs to every vault and cannot be removed.",
        ));
    }
    let mut own = None;
    let s = session(p, open, &mut own)?;
    let id = group_id(&s.vault, path)?;
    let d = recycle::delete_group(&mut s.vault, id, now()).map_err(core)?;
    s.save()?;
    if d.to_bin > 0 {
        done(p, &format!("Group {path} moved to the recycle bin."));
    } else {
        done(p, &format!("Group {path} deleted for good."));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// C03 to C05: attachments.

/// y or Y as the first character means yes.
fn yes() -> bool {
    term::read_line(false, false).is_some_and(|l| l.expose().starts_with(['y', 'Y']))
}

fn attachment_export(p: &Parsed, open: &mut Option<Session>) -> Res {
    let a = rest(p, open);
    let (path, name, file) = (a[0], a[1], a.get(2).copied());
    let to_stdout = p.flag("stdout");
    if !to_stdout && file.is_none() {
        return Err(fail(
            "say where the attachment goes: a file path or --stdout.",
        ));
    }
    if let Some(f) = file.filter(|_| !to_stdout)
        && std::fs::symlink_metadata(f).is_ok()
        && !p.flag("force")
    {
        let asked = term::stdin_tty() && !p.quiet() && {
            term::prompt(&format!("{f} exists. Replace it? [y/N] "), false);
            yes()
        };
        if !asked {
            return Err(fail(format!(
                "{f} exists and was left alone. Add --force to replace it."
            )));
        }
    }
    let mut own = None;
    let s = session(p, open, &mut own)?;
    let id = entry_id(&s.vault, path)?;
    let data = attachments::export(&s.vault, id, name)
        .ok_or_else(|| fail(format!("{path} has no attachment called {name}.")))?;
    match file.filter(|_| !to_stdout) {
        None => term::out_bytes(data.expose())
            .map_err(|e| fail(format!("cannot write to standard output: {e}.")))?,
        Some(f) => {
            storage::write_export(std::path::Path::new(f), data.expose())
                .map_err(|e| fail(format!("cannot write {f}: {}.", e.kind())))?;
            done(p, &format!("Attachment {name} of {path} written to {f}."));
        }
    }
    Ok(())
}

fn attachment_import(p: &Parsed, open: &mut Option<Session>) -> Res {
    let a = rest(p, open);
    let (path, name, file) = (a[0], a[1], a[2]);
    let mut own = None;
    let s = session(p, open, &mut own)?;
    let id = entry_id(&s.vault, path)?;
    let force = p.flag("force");
    if !force && entry(&s.vault, id).is_some_and(|e| attachments::find(e, name).is_some()) {
        return Err(fail(format!(
            "{path} already has an attachment called {name}. Add --force to replace it."
        )));
    }
    let data = storage::read_limited(std::path::Path::new(file), attachments::Limits::DEFAULT.one)
        .map_err(|e| fail(format!("cannot read {file}: {}.", e.kind())))?;
    attachments::import(
        &mut s.vault,
        id,
        name,
        data,
        force,
        &attachments::Limits::DEFAULT,
        now(),
    )
    .map_err(core)?;
    s.save()?;
    done(p, &format!("{file} attached to {path} as {name}."));
    Ok(())
}

fn attachment_rm(p: &Parsed, open: &mut Option<Session>) -> Res {
    let a = rest(p, open);
    let (path, name) = (a[0], a[1]);
    let mut own = None;
    let s = session(p, open, &mut own)?;
    let id = entry_id(&s.vault, path)?;
    if !entry(&s.vault, id).is_some_and(|e| attachments::find(e, name).is_some()) {
        return Err(fail(format!("{path} has no attachment called {name}.")));
    }
    attachments::remove_named(&mut s.vault, id, name, now()).map_err(core)?;
    s.save()?;
    done(p, &format!("Attachment {name} removed from {path}."));
    Ok(())
}

// ---------------------------------------------------------------------------
// C08 db-create, C17 import, C09 db-edit (INT-10.37 to INT-10.39).

/// `-t` (M10-77): a whole number from 100 to 5,000.
fn decryption_time(p: &Parsed) -> Res<Option<u32>> {
    let Some(v) = p.value("decryption-time") else {
        return Ok(None);
    };
    let ms = v
        .parse::<u32>()
        .map_err(|_| fail(format!("{v} is not a whole number of milliseconds.")))?;
    if !(100..=5000).contains(&ms) {
        return Err(fail("the unlock time must be 100 to 5000 ms."));
    }
    Ok(Some(ms))
}

/// M10-78 and M10-79: the new password, typed twice; an empty one only
/// after a yes.
fn new_password(quiet: bool) -> Res<SecretString> {
    let first = term::read_secret("Password for the new vault (Return for none): ", quiet);
    if first.is_empty() {
        term::prompt("Use an empty password? [y/N] ", quiet);
        if yes() {
            return Ok(first);
        }
        return Err(fail("no password chosen. Nothing was changed."));
    }
    let second = term::read_secret("Same password again: ", quiet);
    if !ct_eq(first.expose().as_bytes(), second.expose().as_bytes()) {
        return Err(fail(
            "the two passwords are not the same. Nothing was changed.",
        ));
    }
    Ok(first)
}

/// INT-10.38 step 3: an existing key file is read and left as it is; a
/// missing one is made as XML 2.0 with mode 0400 (FMT-18.20 to FMT-18.22).
fn new_key_file(path: &str) -> Res<larsal_format::keyfile::KeyFileKey> {
    let cannot = |why: String| fail(format!("cannot use {path} as a key file: {why}"));
    if std::fs::symlink_metadata(path).is_err() {
        let bytes = larsal_format::keyfile::create_key_file()
            .map_err(|e| cannot(vault::open_error(&e, "", &vault::file_name(path))))?;
        vault::write_new(path, bytes.expose(), 0o400).map_err(|e| {
            cannot(vault::key_file_text(
                &larsal_format::error::KeyFileReason::Io(e.kind()),
                &vault::file_name(path),
            ))
        })?;
    }
    vault::load_key(path).map_err(cannot)
}

/// The key parts of db-create and import (INT-10.38 steps 2 and 3).
fn new_creds(p: &Parsed, key_path: Option<&str>) -> Res<Creds> {
    let password = if p.flag("set-password") {
        Some(new_password(p.quiet())?)
    } else {
        None
    };
    let key_file = key_path.map(new_key_file).transpose()?;
    Ok(Creds::new(password, key_file))
}

/// The clock of the KDF benchmark (CRY-02.28, LD-72, F-098): the thread's
/// CPU time, as the window app's wizard measures, so a busy Mac cannot tune
/// a weaker KDF.
const MEASURE_CLOCK: larsal_crypto::kdf::Clock = larsal_platform::macos::thread_cpu_time;

/// INT-10.38 step 5 and INT-10.20: Larsal's defaults timed for `-t` or 1,000
/// ms, written as a new file with mode 0600 that replaces nothing.
fn write_vault(p: &Parsed, path: &str, mut v: Vault, creds: &Creds, ms: Option<u32>) -> Res {
    let mut host = vault::host();
    let target = ms.unwrap_or(1000);
    let kdf = settings::tune(&v.encryption.kdf, target, &mut host, MEASURE_CLOCK)
        .map_err(|_| fail("the key derivation could not be tuned on this Mac."))?;
    v.encryption.kdf = kdf;
    if let Some(ms) = ms
        && !p.quiet()
    {
        let (count, word) = match kdf {
            Kdf::AesKdf { rounds } => (rounds, "rounds"),
            Kdf::Argon2 { iterations, .. } => (iterations, "iterations"),
        };
        term::out(&format!(
            "Key derivation tuned to about {ms} ms on this Mac: {count} {word}."
        ));
    }
    let file = match larsal_format::save(&v, &creds.get(), None, &mut host, &Limits::DEFAULT, None)
    {
        Ok(Saved::File(f)) => f,
        _ => {
            return Err(fail(format!(
                "could not save {path}: the vault could not be written."
            )));
        }
    };
    vault::write_new(path, &file.bytes, storage::OWNER_ONLY).map_err(|e| {
        if e.kind() == std::io::ErrorKind::AlreadyExists {
            fail(format!("{path} is taken: a file is already there."))
        } else {
            fail(format!("cannot write {path}: {}.", e.kind()))
        }
    })
}

fn cores() -> u64 {
    std::thread::available_parallelism().map_or(1, |n| u64::try_from(n.get()).unwrap_or(1))
}

/// Before any prompt: `-t`, no key part (M10-76), the key file equal to
/// the vault (FMT-18.24).
fn new_vault_checks(p: &Parsed, path: &str) -> Res<Option<u32>> {
    let ms = decryption_time(p)?;
    if let Some(k) = p.value("set-key-file")
        && vault::same_target(k, path)
    {
        return Err(fail(vault::vault_as_key_file()));
    }
    Ok(ms)
}

fn db_create(p: &Parsed) -> Res {
    let path = p.args[0].as_str();
    if std::fs::symlink_metadata(path).is_ok() {
        return Err(fail(format!("{path} is taken: a file is already there.")));
    }
    let ms = new_vault_checks(p, path)?;
    let key_path = p.value("set-key-file");
    if !p.flag("set-password") && key_path.is_none() {
        return Err(fail(
            "a vault needs a password, a key file or both. Give --set-password, --set-key-file or both.",
        ));
    }
    let creds = new_creds(p, key_path)?;
    let v = settings::new_vault("", now(), cores()).map_err(core)?;
    write_vault(p, path, v, &creds, ms)?;
    done(p, &format!("New vault {path} saved."));
    Ok(())
}

fn import_cmd(p: &Parsed) -> Res {
    let (xml, path) = (p.args[0].as_str(), p.args[1].as_str());
    let key_path = p.value("set-key-file");
    let has = p.flag("set-password") || key_path.is_some();
    import::xml::check_target(std::path::Path::new(path), has).map_err(|e| {
        fail(match e {
            import::ImportError::XmlExists => "File already exists.",
            _ => "No key set, nothing created.",
        })
    })?;
    let ms = new_vault_checks(p, path)?;
    let bytes = import::read_file(std::path::Path::new(xml), import::MAX_FILE).map_err(|e| {
        let why = match e {
            import::ImportError::Open(kind) => kind.to_string(),
            import::ImportError::TooLarge(_) => "it is too large".to_owned(),
            _ => "it does not exist".to_owned(),
        };
        fail(format!("cannot read {xml}: {why}."))
    })?;
    let mut v = import::xml::read(bytes.expose(), now()).map_err(|e| {
        fail(match e {
            import::ImportError::XmlProtected => {
                "Encrypted values are not allowed in a plain XML document."
            }
            import::ImportError::XmlNoRoot => "No root group.",
            _ => "the XML document cannot be read.",
        })
    })?;
    drop(bytes);
    let creds = new_creds(p, key_path)?;
    v.encryption = settings::new_vault("", now(), cores())
        .map_err(core)?
        .encryption;
    write_vault(p, path, v, &creds, ms)?;
    done(p, &format!("New vault {path} made from {xml}."));
    Ok(())
}

fn db_edit(p: &Parsed, open: &mut Option<Session>) -> Res {
    let (set_pw, unset_pw) = (p.flag("set-password"), p.flag("unset-password"));
    let (set_key, unset_key) = (p.value("set-key-file"), p.flag("unset-key-file"));
    if set_pw && unset_pw {
        return Err(fail(
            "--set-password and --unset-password exclude each other.",
        ));
    }
    if set_key.is_some() && unset_key {
        return Err(fail(
            "--set-key-file and --unset-key-file exclude each other.",
        ));
    }
    let mut own = None;
    let target = open
        .as_ref()
        .map_or_else(|| p.arg(0).unwrap_or("").to_owned(), |s| s.path.clone());
    if let Some(k) = set_key
        && vault::same_target(k, &target)
    {
        return Err(fail(vault::vault_as_key_file()));
    }
    let s = session(p, open, &mut own)?;
    let path = s.path.clone();
    if !set_pw && !unset_pw && set_key.is_none() && !unset_key {
        done(p, &format!("Nothing changed; {path} was not saved."));
        return Ok(());
    }
    let (has_pw, has_key) = (s.creds.password.is_some(), s.creds.key_file.is_some());
    if unset_pw && !has_pw {
        return Err(fail(format!("{path} has no password to remove.")));
    }
    if unset_key && !has_key {
        return Err(fail(format!("{path} has no key file to remove.")));
    }
    let left_pw = set_pw || (has_pw && !unset_pw);
    let left_key = set_key.is_some() || (has_key && !unset_key);
    // F-107: the `--hw-key` slot stays a key part.
    if !left_pw && !left_key && s.creds.hardware.is_none() {
        return Err(fail(format!(
            "this would leave {path} with no key part at all. Nothing was changed."
        )));
    }
    let password = if set_pw {
        Some(new_password(p.quiet())?)
    } else {
        None
    };
    let key = set_key.map(new_key_file).transpose()?;
    if unset_pw {
        s.creds.password = None;
    }
    if password.is_some() {
        s.creds.password = password;
    }
    s.keep_password();
    if unset_key {
        s.creds.key_file = None;
    }
    if key.is_some() {
        s.creds.key_file = key;
    }
    settings::key_changed(&mut s.vault.meta, now());
    s.save()?;
    done(p, &format!("New credentials of {path} saved."));
    Ok(())
}

// ---------------------------------------------------------------------------
// C19 merge (INT-10.40).

fn merge_cmd(p: &Parsed, open: &mut Option<Session>) -> Res {
    let source = rest(p, open)[0];
    let from = Unlock {
        key_file: p.value("key-file-from"),
        no_password: p.flag("no-password-from"),
        hw_key: p.value("hw-key-from"),
        quiet: p.quiet(),
        slow: p.flag("allow-slow-unlock"),
    };
    let same = p.flag("same-credentials");
    if same {
        vault::check_vault(source)?;
    } else {
        vault::check_unlock(source, &from)?;
    }
    let mut own = None;
    let s = session(p, open, &mut own)?;
    let target = s.path.clone();
    let src = if same {
        let creds = std::mem::take(&mut s.creds);
        match vault::open(source, creds, &from) {
            Ok(mut src) => {
                s.creds = std::mem::take(&mut src.creds);
                src
            }
            Err((creds, text)) => {
                s.creds = creds;
                return Err(fail(format!(
                    "cannot open {source} with the credentials of {target}: {text}"
                )));
            }
        }
    } else {
        let creds = vault::read_creds(source, &from)?;
        vault::open(source, creds, &from).map_err(|(_, text)| fail(text))?
    };
    let o = merge::Options {
        dry_run: p.flag("dry-run"),
        ..merge::Options::new(merge::Kind::CommandLine)
    };
    let merged = merge::merge(&mut s.vault, &src.vault, &o, now()).map_err(core)?;
    if !p.quiet() {
        for c in &merged.changes {
            term::out(&c.line());
        }
    }
    if !merged.changes.is_empty() && !o.dry_run {
        s.save()?;
        done(
            p,
            &format!("{target} saved with the changes from {source}."),
        );
    } else {
        done(p, &format!("{target} is unchanged."));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// C02 analyze, C14 export.

fn analyze(p: &Parsed, open: &mut Option<Session>) -> Res {
    let Some(file) = p.value("hash-file") else {
        return Err(fail(
            "give the list of leaked hashes with --hash-file FILE.",
        ));
    };
    let mut own = None;
    let s = session(p, open, &mut own)?;
    let f = std::fs::File::open(file)
        .map_err(|e| fail(format!("cannot read {file}: {}.", e.kind())))?;
    if !p.quiet() {
        term::out(&format!(
            "Checking every password against {file}. This can need minutes for a big list."
        ));
    }
    let found = breach::offline_check(&s.vault, std::io::BufReader::new(f))
        .map_err(|e| fail(e.message()))?;
    for f in found {
        let line = match f.count {
            0 => format!("Leaked password: {}", f.path),
            1 => format!("Leaked password: {} (in the list once)", f.path),
            n => format!("Leaked password: {} (in the list {n} times)", f.path),
        };
        term::out(&line);
    }
    Ok(())
}

fn export_cmd(p: &Parsed, open: &mut Option<Session>) -> Res {
    let format = export::Format::from_option(p.value("format")).map_err(fail)?;
    let mut own = None;
    let s = session(p, open, &mut own)?;
    let mut warning = String::from(
        "Warning: this export is not encrypted. Anyone who can read it can read every password in it.",
    );
    if format == export::Format::Csv {
        warning.push(' ');
        warning.push_str(export::FORMULA_NOTE);
    }
    term::err(&warning);
    let bytes = match format {
        export::Format::Xml => {
            export::xml::xml(&s.vault).map_err(|e| fail(format!("the export failed: {e}.")))?
        }
        export::Format::Csv => export::csv::csv(&s.vault, now()),
        export::Format::Html => export::html::html(
            &s.vault,
            &export::html::Options {
                sort: export::html::Sort::NameAscending,
                path: &s.path,
                icon: None,
            },
        ),
    };
    if term::stdout_tty() {
        let text = SecretString::new(String::from_utf8_lossy(bytes.expose()).into_owned());
        term::out_pair("", text.expose());
    } else {
        term::out_bytes(bytes.expose())
            .map_err(|e| fail(format!("cannot write to standard output: {e}.")))?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// C11 passphrase, C13 estimate, C15 generate.

fn generate(p: &Parsed) -> Res {
    let o = generator(p)?;
    term::out_pair("", generated(&o)?.expose());
    Ok(())
}

fn passphrase_cmd(p: &Parsed) -> Res {
    let words = match p.value("words") {
        None => 7,
        Some(v) => v
            .parse::<u32>()
            .ok()
            .filter(|n| (1..=passphrase::MAX_WORDS).contains(n))
            .ok_or_else(|| fail(format!("{v} is not a usable word count.")))?,
    };
    let owned;
    let list = match p.value("word-list") {
        None => wordlist::builtin(),
        Some(path) => {
            let bytes = storage::read_limited(
                std::path::Path::new(path),
                u64::try_from(wordlist::MAX_FILE).unwrap_or(u64::MAX) + 1,
            )
            .map_err(|e| {
                if e.kind() == std::io::ErrorKind::FileTooLarge {
                    fail(format!("the word list {path} is too big: at most 4 MiB."))
                } else {
                    fail(format!("cannot read the word list {path}: {}.", e.kind()))
                }
            })?;
            owned = wordlist::parse(bytes.expose()).map_err(|e| {
                fail(match e {
                    wordlist::ListError::NotUtf8 => format!("the word list {path} is not UTF-8 text."),
                    wordlist::ListError::TooBig => format!(
                        "the word list {path} is too big: at most 4 MiB, 500000 words and 256 characters a word."
                    ),
                })
            })?;
            &owned
        }
    };
    if list.is_empty() {
        return Err(fail("the word list holds no words."));
    }
    if list.is_small() && !p.quiet() {
        term::err(&format!(
            "Warning: the word list has {} words, fewer than the 1296 recommended.",
            list.len()
        ));
    }
    let phrase = passphrase::generate(&passphrase::Options::command_line(words), list)
        .map_err(|_| fail("could not get random numbers from macOS."))?;
    term::out_pair("", phrase.expose());
    Ok(())
}

fn estimate(p: &Parsed) -> Res {
    if term::stdin_tty() {
        term::prompt("Password to rate: ", p.quiet());
    }
    let pw = term::read_line(true, p.quiet()).unwrap_or_else(|| SecretString::new(String::new()));
    let pw = pw.expose();
    let bits = health::bits_with(&health::zxcvbn_bits, pw, &[]);
    let n = pw.chars().count();
    term::out(&format!(
        "Characters {n}\tBits {bits:.3}\tLog10 {:.3}",
        bits * std::f64::consts::LOG10_2
    ));
    if p.flag("advanced") {
        // Byte offsets of each character: the parts are slices of the
        // typed password, never another copy of it.
        let at: Vec<usize> = pw
            .char_indices()
            .map(|(i, _)| i)
            .chain(std::iter::once(pw.len()))
            .collect();
        for part in health::zxcvbn_parts(pw) {
            let text = at
                .get(part.start)
                .zip(at.get(part.end))
                .and_then(|(&a, &b)| pw.get(a..b))
                .unwrap_or("");
            let bits = format!("\t{:.3}", part.bits);
            term::out_parts(&[part.kind, "\t", text, &bits]);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    /// F-098 (LD-72): db-create and import tune the KDF by the thread's CPU
    /// time, which stands still while the thread waits, so other work on a
    /// busy Mac cannot make the measured run look slow.
    #[test]
    fn f_098_kdf_tuning_clock_is_the_threads_cpu_time() {
        let before = super::MEASURE_CLOCK();
        std::thread::sleep(std::time::Duration::from_millis(200));
        let slept = super::MEASURE_CLOCK().saturating_sub(before);
        assert!(slept < std::time::Duration::from_millis(50), "{slept:?}");
    }
}
