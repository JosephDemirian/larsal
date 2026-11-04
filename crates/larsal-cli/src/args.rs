//! The commands, their options and arguments (INT-10 "Inputs and outputs"),
//! the option parser (INT-10.2) and the help texts (M10-03, INT-10.3). The
//! reference spellings are hidden aliases (D-INT10-1): accepted, never shown.

/// One option.
pub struct Opt {
    /// The long name without `--`; also the key the commands ask by.
    pub long: &'static str,
    pub short: Option<char>,
    /// The value's name in the help, for an option that takes one.
    pub value: Option<&'static str>,
    pub help: &'static str,
    /// Hidden spellings, written in full (`-y`, `--yubikey`).
    pub aliases: &'static [&'static str],
}

const fn flag(long: &'static str, short: Option<char>, help: &'static str) -> Opt {
    Opt {
        long,
        short,
        value: None,
        help,
        aliases: &[],
    }
}

const fn val(
    long: &'static str,
    short: Option<char>,
    value: &'static str,
    help: &'static str,
) -> Opt {
    Opt {
        long,
        short,
        value: Some(value),
        help,
        aliases: &[],
    }
}

/// U01 to U05 (INT-10 "Unlock options").
const UNLOCK: &[Opt] = &[
    val(
        "key-file",
        Some('k'),
        "PATH",
        "Use the key file PATH to unlock.",
    ),
    flag(
        "no-password",
        None,
        "The vault has no password; do not ask for one.",
    ),
    Opt {
        aliases: &["-y", "--yubikey"],
        ..val(
            "hw-key",
            None,
            "SLOT[:SERIAL]",
            "Use the security key in slot 1 or 2 to unlock.",
        )
    },
    flag(
        "quiet",
        Some('q'),
        "No prompts, notes or success lines; errors still print.",
    ),
    flag(
        "allow-slow-unlock",
        None,
        "Go ahead with an unlock that needs much memory or time.",
    ),
];

const QUIET: &[Opt] = &[flag(
    "quiet",
    Some('q'),
    "No prompts, notes or success lines; errors still print.",
)];

/// G: the generator options (FEA-02.21).
const GEN: &[Opt] = &[
    val(
        "length",
        Some('L'),
        "N",
        "Number of characters, 1 to 10000 (default 32).",
    ),
    flag("lower", Some('l'), "Use lower-case letters."),
    flag("upper", Some('U'), "Use upper-case letters."),
    flag("numeric", Some('n'), "Use digits."),
    flag("special", Some('s'), "Use the six groups of symbols."),
    flag("extended", Some('e'), "Use extended Latin characters."),
    val("exclude", Some('x'), "CHARS", "Never use these characters."),
    val(
        "custom",
        Some('c'),
        "CHARS",
        "Use these characters as one more group.",
    ),
    flag(
        "exclude-similar",
        None,
        "Leave out characters that look alike.",
    ),
    flag(
        "every-group",
        None,
        "Use at least one character of every group.",
    ),
];

const ENTRY_FIELDS: &[Opt] = &[
    val("username", Some('u'), "TEXT", "The user name."),
    val("url", None, "TEXT", "The URL."),
    val(
        "notes",
        None,
        "TEXT",
        "The notes; \\n in TEXT starts a new line.",
    ),
    flag(
        "password-prompt",
        Some('p'),
        "Ask for the entry password on the terminal or read it from stdin.",
    ),
    flag(
        "generate",
        Some('g'),
        "Make the entry password with the generator options.",
    ),
];

const EDIT: &[Opt] = &[val("title", Some('t'), "TEXT", "The new title.")];

const LS: &[Opt] = &[
    flag(
        "recursive",
        Some('R'),
        "Also list every group inside, indented.",
    ),
    flag(
        "flatten",
        Some('f'),
        "Start each line with its group's path instead of indenting.",
    ),
];

const SHOW: &[Opt] = &[
    val(
        "attributes",
        Some('a'),
        "NAME",
        "Print only the value of field NAME; give it again for more.",
    ),
    flag(
        "show-protected",
        Some('s'),
        "Print protected values instead of (hidden).",
    ),
    flag("all", None, "Print every field."),
    flag("show-attachments", None, "List the attached files."),
    flag("totp", Some('t'), "Print the current one-time password."),
];

const CLIP: &[Opt] = &[
    val(
        "attribute",
        Some('a'),
        "NAME",
        "Copy field NAME instead of Password.",
    ),
    flag("totp", Some('t'), "Copy the current one-time password."),
    flag(
        "best-match",
        Some('b'),
        "Treat ENTRY as a search term for the title.",
    ),
];

const ANALYZE: &[Opt] = &[Opt {
    aliases: &["--hibp"],
    ..val(
        "hash-file",
        Some('H'),
        "FILE",
        "The list of leaked SHA-1 hashes to check against.",
    )
}];

const ESTIMATE: &[Opt] = &[flag(
    "advanced",
    Some('a'),
    "Also print each part the estimate found.",
)];

const EXPORT: &[Opt] = &[val(
    "format",
    Some('f'),
    "FORMAT",
    "xml (default), csv or html.",
)];

const PASSPHRASE: &[Opt] = &[
    val("words", Some('W'), "N", "Number of words (default 7)."),
    val(
        "word-list",
        Some('w'),
        "PATH",
        "Take the words from this file instead of the built-in list.",
    ),
];

const NEW_VAULT: &[Opt] = &[
    flag(
        "set-password",
        Some('p'),
        "Ask for the new vault's password.",
    ),
    Opt {
        aliases: &["-k"],
        ..val(
            "set-key-file",
            None,
            "PATH",
            "Use the key file PATH; it is made when missing.",
        )
    },
    val(
        "decryption-time",
        Some('t'),
        "MS",
        "Tune the unlock to take about MS milliseconds (100 to 5000).",
    ),
];

const DB_EDIT: &[Opt] = &[
    flag("set-password", Some('p'), "Ask for a new password."),
    val(
        "set-key-file",
        None,
        "PATH",
        "Use the key file PATH; it is made when missing.",
    ),
    flag("unset-password", None, "Remove the password."),
    flag("unset-key-file", None, "Remove the key file."),
];

const MERGE: &[Opt] = &[
    flag(
        "same-credentials",
        Some('s'),
        "Unlock SOURCE with the key of VAULT.",
    ),
    val(
        "key-file-from",
        None,
        "PATH",
        "Use the key file PATH to unlock SOURCE.",
    ),
    flag(
        "no-password-from",
        None,
        "SOURCE has no password; do not ask for one.",
    ),
    Opt {
        aliases: &["--yubikey-from"],
        ..val(
            "hw-key-from",
            None,
            "SLOT[:SERIAL]",
            "Use the security key in slot 1 or 2 to unlock SOURCE.",
        )
    },
    flag(
        "dry-run",
        Some('d'),
        "List the changes without saving them.",
    ),
];

const ATT_EXPORT: &[Opt] = &[
    flag("stdout", None, "Write the attachment to standard output."),
    flag("force", Some('f'), "Replace FILE if it exists."),
];

const ATT_IMPORT: &[Opt] = &[flag(
    "force",
    Some('f'),
    "Replace an attachment of that name.",
)];

const NONE: &[Opt] = &[];

/// One command of the table (C01 to C28).
pub struct Cmd {
    pub name: &'static str,
    pub help: &'static str,
    /// In order; `[NAME]` is optional. A first `VAULT` is the open vault in
    /// the shell (INT-10.45).
    pub args: &'static [&'static str],
    pub opts: &'static [&'static [Opt]],
    /// The hidden reference spelling of the name (D-INT10-1).
    pub alias: Option<&'static str>,
}

impl Cmd {
    /// True for the commands that unlock their VAULT (INT-10 "Unlock options").
    pub fn unlocks(&self) -> bool {
        self.args.first() == Some(&"VAULT") && self.name != "db-create"
    }

    /// Every option of the command, in help order.
    fn options(&self) -> impl Iterator<Item = &'static Opt> {
        let groups: &'static [&'static [Opt]] = self.opts;
        groups.iter().flat_map(|g| g.iter())
    }

    /// The positional arguments `parse` takes: without VAULT in the shell
    /// while a vault is open (INT-10.45).
    fn positionals(&self, vault_open: bool) -> &'static [&'static str] {
        let args: &'static [&'static str] = self.args;
        args.get(usize::from(vault_open && self.unlocks())..)
            .unwrap_or_default()
    }
}

const fn cmd(
    name: &'static str,
    args: &'static [&'static str],
    opts: &'static [&'static [Opt]],
    help: &'static str,
) -> Cmd {
    Cmd {
        name,
        help,
        args,
        opts,
        alias: None,
    }
}

/// C01 to C28, in the order of the help.
pub const COMMANDS: &[Cmd] = &[
    cmd(
        "add",
        &["VAULT", "ENTRY"],
        &[ENTRY_FIELDS, GEN, UNLOCK],
        "Make a new entry.",
    ),
    cmd(
        "analyze",
        &["VAULT"],
        &[ANALYZE, UNLOCK],
        "Check the passwords against a list of leaked password hashes.",
    ),
    cmd(
        "attachment-export",
        &["VAULT", "ENTRY", "NAME", "[FILE]"],
        &[ATT_EXPORT, UNLOCK],
        "Write an attachment to a file or to standard output.",
    ),
    cmd(
        "attachment-import",
        &["VAULT", "ENTRY", "NAME", "FILE"],
        &[ATT_IMPORT, UNLOCK],
        "Attach a file to an entry.",
    ),
    cmd(
        "attachment-rm",
        &["VAULT", "ENTRY", "NAME"],
        &[UNLOCK],
        "Delete one of an entry's attachments.",
    ),
    cmd(
        "clip",
        &["VAULT", "ENTRY", "[SECONDS]"],
        &[CLIP, UNLOCK],
        "Put a field on the clipboard and clear it later.",
    ),
    cmd("close", &[], &[NONE], "Close the vault open in the shell."),
    cmd(
        "db-create",
        &["VAULT"],
        &[NEW_VAULT, QUIET],
        "Make a new, empty vault.",
    ),
    cmd(
        "db-edit",
        &["VAULT"],
        &[DB_EDIT, UNLOCK],
        "Change a vault's password or key file.",
    ),
    cmd(
        "db-info",
        &["VAULT"],
        &[UNLOCK],
        "Print facts and counts about a vault.",
    ),
    Cmd {
        alias: Some("diceware"),
        ..cmd(
            "passphrase",
            &[],
            &[PASSPHRASE, QUIET],
            "Make a random passphrase from a word list.",
        )
    },
    cmd(
        "edit",
        &["VAULT", "ENTRY"],
        &[EDIT, ENTRY_FIELDS, GEN, UNLOCK],
        "Change an entry's fields.",
    ),
    cmd(
        "estimate",
        &[],
        &[ESTIMATE, QUIET],
        "Rate how hard a password is to guess.",
    ),
    cmd(
        "export",
        &["VAULT"],
        &[EXPORT, UNLOCK],
        "Print the whole vault, not encrypted, as XML, CSV or HTML.",
    ),
    cmd("generate", &[], &[GEN, QUIET], "Make a random password."),
    cmd(
        "help",
        &["[COMMAND]"],
        &[NONE],
        "Show the commands, or one command's options.",
    ),
    cmd(
        "import",
        &["XML", "VAULT"],
        &[NEW_VAULT, QUIET],
        "Make a new vault from a plain XML document.",
    ),
    cmd(
        "ls",
        &["VAULT", "[GROUP]"],
        &[LS, UNLOCK],
        "List a group's entries and groups.",
    ),
    cmd(
        "merge",
        &["VAULT", "SOURCE"],
        &[MERGE, UNLOCK],
        "Bring the changes of another vault into this one.",
    ),
    cmd("mkdir", &["VAULT", "GROUP"], &[UNLOCK], "Make a new group."),
    cmd(
        "mv",
        &["VAULT", "ENTRY", "GROUP"],
        &[UNLOCK],
        "Put an entry in a different group.",
    ),
    cmd(
        "open",
        &["VAULT"],
        &[UNLOCK],
        "Unlock a vault and keep it open for several commands.",
    ),
    cmd(
        "rm",
        &["VAULT", "ENTRY"],
        &[UNLOCK],
        "Move an entry to the recycle bin, or delete it.",
    ),
    cmd(
        "rmdir",
        &["VAULT", "GROUP"],
        &[UNLOCK],
        "Move a group to the recycle bin, or delete it.",
    ),
    cmd(
        "search",
        &["VAULT", "TERM"],
        &[UNLOCK],
        "Find entries with the search language.",
    ),
    cmd(
        "show",
        &["VAULT", "ENTRY"],
        &[SHOW, UNLOCK],
        "Print an entry's fields.",
    ),
    cmd("exit", &[], &[NONE], "Leave the shell."),
    cmd("quit", &[], &[NONE], "Leave the shell."),
];

/// C27 and C28 exist only in the shell; export and import only outside it.
pub fn lookup(name: &str, shell: bool) -> Option<&'static Cmd> {
    let c = COMMANDS
        .iter()
        .find(|c| c.name == name || c.alias == Some(name))?;
    let shell_only = matches!(c.name, "exit" | "quit");
    let outside_only = matches!(c.name, "export" | "import");
    let ok = if shell { !outside_only } else { !shell_only };
    ok.then_some(c)
}

/// A parsed command line.
pub struct Parsed {
    pub cmd: &'static Cmd,
    /// Every option given, in order, with its value.
    given: Vec<(&'static str, Option<String>)>,
    pub args: Vec<String>,
}

impl Parsed {
    pub fn flag(&self, long: &str) -> bool {
        self.given.iter().any(|(l, _)| *l == long)
    }

    /// The last value given (INT-10.2).
    pub fn value(&self, long: &str) -> Option<&str> {
        self.given
            .iter()
            .rev()
            .find(|(l, _)| *l == long)
            .and_then(|(_, v)| v.as_deref())
    }

    /// Every value given, in order (show `-a`).
    pub fn values(&self, long: &str) -> Vec<&str> {
        self.given
            .iter()
            .filter(|(l, _)| *l == long)
            .filter_map(|(_, v)| v.as_deref())
            .collect()
    }

    /// A value that is not empty (INT-10.22: empty counts as not given).
    pub fn text(&self, long: &str) -> Option<&str> {
        self.value(long).filter(|v| !v.is_empty())
    }

    pub fn quiet(&self) -> bool {
        self.flag("quiet")
    }

    pub fn arg(&self, i: usize) -> Option<&str> {
        self.args.get(i).map(String::as_str)
    }
}

/// The `<problem>` of M10-02.
#[derive(Debug, PartialEq, Eq)]
pub enum Problem {
    Unknown(String),
    NeedsValue(String),
    Missing(String),
    Extra(String),
    /// A `--hw-key` value that is not `SLOT[:SERIAL]` (INT-07.27, LD-175).
    BadSlot(String),
    /// `-h` or `--help` (INT-10.3): print the command's help, exit 0.
    Help,
    /// A password given to estimate (M10-92, D-INT10-4).
    PasswordArgument,
}

impl core::fmt::Display for Problem {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Unknown(o) => write!(f, "unknown option {o}"),
            Self::NeedsValue(o) => write!(f, "{o} needs a value"),
            Self::Missing(a) => write!(f, "{a} is missing"),
            Self::Extra(a) => write!(f, "unexpected argument {a}"),
            Self::BadSlot(v) => write!(f, "{v} is not a slot (1 or 2) with an optional serial"),
            Self::Help => write!(f, "help asked for"),
            Self::PasswordArgument => write!(f, "estimate takes no password argument"),
        }
    }
}

/// INT-07.27: `SLOT` or `SLOT:SERIAL`, slot 1 or 2, serial a decimal
/// number from 0 to 4,294,967,295.
pub fn hw_key_ok(value: &str) -> bool {
    let (slot, serial) = match value.split_once(':') {
        Some((slot, serial)) => (slot, Some(serial)),
        None => (value, None),
    };
    matches!(slot, "1" | "2")
        && serial.is_none_or(|s| {
            !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()) && s.parse::<u32>().is_ok()
        })
}

/// M10-02.
pub fn usage_error(cmd: &str, p: &Problem) -> String {
    format!("larsal {cmd}: {p}. Run larsal help {cmd} to see its options.")
}

/// INT-10.2: long options as `--name value` or `--name=value`, short ones
/// as `-x value`, `-xvalue` or `-x=value`, short flags combined (`-ln`),
/// options anywhere, `--` ends them. A value option takes the next word
/// whatever it looks like (`-u -h` is the user name `-h`); given twice it
/// keeps the last value, except `show -a`, which keeps all. `-h` or
/// `--help` outside a value asks for Larsal's own help at once (INT-10.3).
/// The reference spellings are hidden aliases (D-INT10-1). `vault_open`:
/// in the shell with a vault open, the commands that unlock take no VAULT
/// (INT-10.45).
///
/// The first problem found is the one reported, in this order: an unknown
/// option, a value given to a flag (`--lower=x`) or `-h`, as each comes;
/// then a value option at the end with no value, a missing argument, a
/// password given to estimate, a bad `--hw-key` value. An extra argument
/// is reported where it comes.
pub fn parse(cmd: &'static Cmd, words: &[String], vault_open: bool) -> Result<Parsed, Problem> {
    // An unknown option that also stands after a `--` reads as an extra
    // argument (the old parser's report, kept).
    let unknown = |arg: String| {
        if words
            .iter()
            .skip_while(|w| *w != "--")
            .skip(1)
            .any(|w| *w == arg)
        {
            Problem::Extra(arg)
        } else {
            Problem::Unknown(arg)
        }
    };
    let long = |name: &str| {
        cmd.options().find(|o| {
            o.long == name || o.aliases.iter().any(|a| a.strip_prefix("--") == Some(name))
        })
    };
    let short = |c: char| {
        cmd.options().find(|o| {
            o.short == Some(c)
                || o.aliases.iter().any(|a| {
                    !a.starts_with("--")
                        && a.strip_prefix('-').and_then(|s| s.chars().next()) == Some(c)
                })
        })
    };
    let positionals = cmd.positionals(vault_open);
    // Every option given, in order; a flag has no value.
    let mut seen: Vec<(&'static str, Option<String>)> = Vec::new();
    let mut args: Vec<String> = Vec::new();
    let (mut pending, mut trailing, mut password) = (None::<&Opt>, false, false);
    for w in words {
        if let Some(o) = pending.take() {
            seen.push((o.long, Some(w.clone())));
        } else if trailing || w == "-" || !w.starts_with('-') {
            if cmd.name == "estimate" {
                // D-INT10-4: a password argument is taken, then refused (M10-92).
                password = true;
            } else if args.len() < positionals.len() {
                args.push(w.clone());
            } else {
                return Err(Problem::Extra(w.clone()));
            }
        } else if w == "--" {
            trailing = true;
        } else if let Some(rest) = w.strip_prefix("--") {
            let (name, value) = rest
                .split_once('=')
                .map_or((rest, None), |(n, v)| (n, Some(v)));
            if name == "help" {
                return Err(value.map_or(Problem::Help, |v| Problem::Extra(v.to_owned())));
            }
            let Some(o) = long(name) else {
                return Err(unknown(format!("--{name}")));
            };
            match (o.value, value) {
                (None, Some(v)) => return Err(Problem::Extra(v.to_owned())),
                (None, None) => seen.push((o.long, None)),
                (Some(_), Some(v)) => seen.push((o.long, Some(v.to_owned()))),
                (Some(_), None) => pending = Some(o),
            }
        } else {
            for (i, c) in w.char_indices().skip(1) {
                if c == 'h' {
                    return Err(Problem::Help);
                }
                let Some(o) = short(c) else {
                    return Err(unknown(format!("-{c}")));
                };
                if o.value.is_none() {
                    seen.push((o.long, None));
                    continue;
                }
                let attached = w.get(i + c.len_utf8()..).unwrap_or_default();
                if attached.is_empty() {
                    pending = Some(o);
                } else {
                    let v = attached.strip_prefix('=').unwrap_or(attached);
                    seen.push((o.long, Some(v.to_owned())));
                }
                break;
            }
        }
    }
    if let Some(o) = pending {
        return Err(Problem::NeedsValue(format!("--{}", o.long)));
    }
    if let Some(missing) = positionals.get(args.len()).filter(|a| !a.starts_with('[')) {
        return Err(Problem::Missing((*missing).to_owned()));
    }
    if password {
        return Err(Problem::PasswordArgument);
    }
    // In help order: a flag once, a value option's last value, every
    // value of `show -a`.
    let mut given = Vec::new();
    for o in cmd.options() {
        let mut values = seen.iter().filter(|(l, _)| *l == o.long).map(|(_, v)| v);
        match o.value {
            None if values.next().is_some() => given.push((o.long, None)),
            Some(_) if o.long == "attributes" => given.extend(values.map(|v| (o.long, v.clone()))),
            Some(_) => given.extend(values.next_back().map(|v| (o.long, v.clone()))),
            None => {}
        }
    }
    for (long, value) in &given {
        if let (&("hw-key" | "hw-key-from"), Some(v)) = (long, value)
            && !hw_key_ok(v)
        {
            return Err(Problem::BadSlot(v.clone()));
        }
    }
    Ok(Parsed { cmd, given, args })
}

/// What a command line came to.
pub enum Outcome {
    /// Run the command.
    Run(Parsed),
    /// The help was printed: exit 0.
    Help,
    /// An error was printed: exit 1.
    Failed,
}

/// Parses; or prints the command's help on stdout (`-h`, `--help`), M10-92
/// for a password given to estimate (D-INT10-4), or M10-02.
pub fn parse_or_report(cmd: &'static Cmd, words: &[String], vault_open: bool) -> Outcome {
    match parse(cmd, words, vault_open) {
        Ok(p) => Outcome::Run(p),
        Err(Problem::Help) => {
            print!("{}", command_help(cmd));
            Outcome::Help
        }
        Err(Problem::PasswordArgument) => {
            crate::term::err(
                "larsal: estimate does not take the password as an argument, because other programs can read arguments. Pipe it in, or type it at the prompt.",
            );
            Outcome::Failed
        }
        Err(e) => {
            crate::term::err(&usage_error(cmd.name, &e));
            Outcome::Failed
        }
    }
}

/// M10-03: the title, the usage line and one line per command (no aliases,
/// no shell-only commands).
pub fn overview() -> String {
    let mut s = String::from(
        "Larsal command line tool.\n\
         Usage: larsal COMMAND [OPTIONS] ARGUMENTS, or larsal -h | -v | --license | --debug-info\n\n\
         Commands:\n",
    );
    for c in COMMANDS
        .iter()
        .filter(|c| !matches!(c.name, "exit" | "quit"))
    {
        s.push_str(&format!("  {:<19} {}\n", c.name, c.help));
    }
    s.push_str("\nRun larsal help COMMAND to see the options of a command.\n");
    s
}

/// INT-10.3: one command's usage, help line, arguments and options.
pub fn command_help(c: &Cmd) -> String {
    let mut s = format!("Usage: larsal {} [OPTIONS]", c.name);
    for a in c.args {
        s.push(' ');
        s.push_str(a);
    }
    s.push_str(&format!("\n{}\n\nOptions:\n", c.help));
    let groups: &[&[Opt]] = c.opts;
    for o in groups.iter().flat_map(|g| g.iter()) {
        let short = o.short.map_or("    ".to_owned(), |c| format!("-{c}, "));
        let name = match o.value {
            Some(v) => format!("{short}--{} {v}", o.long),
            None => format!("{short}--{}", o.long),
        };
        s.push_str(&format!("  {name:<34} {}\n", o.help));
    }
    s.push_str(&format!("  {:<34} {}\n", "-h, --help", "Show this help."));
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn words(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| (*s).to_owned()).collect()
    }

    fn p(name: &str, list: &[&str]) -> Result<Parsed, Problem> {
        parse(lookup(name, false).unwrap(), &words(list), false)
    }

    #[test]
    fn int10_2_forms() {
        for form in [
            &["-L12"][..],
            &["--length=12"],
            &["-L", "12"],
            &["--length", "12"],
        ] {
            assert_eq!(p("generate", form).unwrap().value("length"), Some("12"));
        }
        let x = p("generate", &["-lnL", "40"]).unwrap();
        assert!(x.flag("lower") && x.flag("numeric"));
        assert_eq!(x.value("length"), Some("40"));
        let x = p("ls", &["v", "--", "-R"]).unwrap();
        assert_eq!(x.args, ["v", "-R"]);
        assert!(!x.flag("recursive"));
        let x = p("show", &["-a", "A", "v", "e", "-a", "B"]).unwrap();
        assert_eq!(x.values("attributes"), ["A", "B"]);
        assert_eq!(
            p("generate", &["--bogus"]).err(),
            Some(Problem::Unknown("--bogus".into()))
        );
        assert_eq!(
            p("generate", &["-L"]).err(),
            Some(Problem::NeedsValue("--length".into()))
        );
        assert_eq!(p("ls", &[]).err(), Some(Problem::Missing("VAULT".into())));
        assert_eq!(
            p("ls", &["v", "g", "x"]).err(),
            Some(Problem::Extra("x".into()))
        );
        for bad in ["3", "2:abc", "2:4294967296", "0", "2:", "+1"] {
            assert_eq!(
                p("ls", &["--hw-key", bad, "v"]).err(),
                Some(Problem::BadSlot(bad.into()))
            );
        }
        assert!(p("ls", &["--hw-key=2:4294967295", "v"]).is_ok());
        assert_eq!(
            p("clip", &["v", "e", "-5"]).err(),
            Some(Problem::Unknown("-5".into()))
        );
    }

    #[test]
    fn int10_3_clap_finds_help() {
        assert_eq!(p("ls", &["-qh", "v"]).err(), Some(Problem::Help));
        assert_eq!(p("ls", &["--help"]).err(), Some(Problem::Help));
        assert_eq!(p("show", &["-h"]).err(), Some(Problem::Help));
        let x = p("add", &["-u", "-h", "v", "X"]).unwrap();
        assert_eq!(x.value("username"), Some("-h"));
        assert_eq!(x.args, ["v", "X"]);
        assert_eq!(
            p("generate", &["--", "-h"]).err(),
            Some(Problem::Extra("-h".into()))
        );
    }

    #[test]
    fn int10_33_password_argument_is_refused() {
        for words in [&["pw"][..], &["--", "-x"], &["a", "b"]] {
            assert_eq!(
                p("estimate", words).err(),
                Some(Problem::PasswordArgument),
                "{words:?}"
            );
        }
        assert!(p("estimate", &["-a"]).is_ok());
    }

    #[test]
    fn int10_45_open_vault_takes_the_place_of_vault() {
        let ls = lookup("ls", true).unwrap();
        assert_eq!(parse(ls, &words(&["G"]), true).unwrap().args, ["G"]);
        assert_eq!(
            parse(ls, &words(&["v", "G"]), false).unwrap().args,
            ["v", "G"]
        );
        let create = lookup("db-create", true).unwrap();
        assert_eq!(parse(create, &words(&["n"]), true).unwrap().args, ["n"]);
    }

    /// E0-S7 R9: forms the old parser took the same way, beyond INT-10.2's
    /// test (the old-against-new run of the step 3c record).
    #[test]
    fn int10_2_more_forms() {
        let x = p("generate", &["-L=12"]).unwrap();
        assert_eq!(x.value("length"), Some("12"), "-x=value");
        assert_eq!(x.values("length"), ["12"]);
        let x = p("generate", &["-L", "5", "--length=7", "-l", "-l"]).unwrap();
        assert_eq!(x.values("length"), ["7"], "the last value only");
        assert!(x.flag("lower"));
        assert_eq!(
            p("generate", &["--lower=x"]).err(),
            Some(Problem::Extra("x".into()))
        );
        assert_eq!(
            p("generate", &["--help=x"]).err(),
            Some(Problem::Extra("x".into()))
        );
        assert_eq!(
            p("ls", &["--bogus", "v", "--", "--bogus"]).err(),
            Some(Problem::Extra("--bogus".into()))
        );
        assert_eq!(p("ls", &["-", "g"]).unwrap().args, ["-", "g"]);
    }

    #[test]
    fn int10_4_aliases_are_hidden() {
        assert_eq!(lookup("diceware", false).unwrap().name, "passphrase");
        assert!(lookup("exit", false).is_none() && lookup("exit", true).is_some());
        assert!(lookup("export", true).is_none());
        assert!(p("ls", &["-y", "2", "v"]).unwrap().value("hw-key") == Some("2"));
        assert!(
            p("analyze", &["--hibp", "h", "v"])
                .unwrap()
                .value("hash-file")
                == Some("h")
        );
        assert!(p("analyze", &["--okon", "x", "v"]).is_err());
        let text = overview();
        for c in COMMANDS
            .iter()
            .filter(|c| !matches!(c.name, "exit" | "quit"))
        {
            assert!(text.contains(&format!("  {} ", c.name)), "{}", c.name);
        }
        for alias in ["diceware", "--hibp", "--yubikey", "-y,"] {
            assert!(!text.contains(alias));
            for c in COMMANDS {
                assert!(!command_help(c).contains(alias), "{alias} in {}", c.name);
            }
        }
    }
}
