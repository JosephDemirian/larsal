//! The shell of `open` (INT-10.45 to INT-10.47): plain lines from stdin, one
//! at a time, so piped input works; a prompt only on a terminal; no line
//! history and no idle close (D-INT10-8).

use crate::args::{self, Parsed};
use crate::commands;
use crate::term::{self, Res};
use crate::vault::{self, Session, Unlock};

/// C22 outside the shell: unlock VAULT, then read command lines until
/// `exit`, `quit` or end of input. A failed unlock exits 1.
pub fn open(p: &Parsed) -> Res {
    let mut open = Some(vault::unlock(p.arg(0).unwrap_or(""), &Unlock::of(p))?);
    run(&mut open);
    Ok(())
}

fn run(open: &mut Option<Session>) {
    loop {
        if term::stdin_tty() {
            let name = open.as_ref().map_or_else(
                || "larsal> ".to_owned(),
                |s| format!("larsal ({})> ", s.name()),
            );
            term::prompt(&name, false);
        }
        let Some(line) = term::read_line(false, false) else {
            break;
        };
        let words = split(line.expose());
        drop(line);
        let Some(first) = words.first() else {
            continue;
        };
        if matches!(first.as_str(), "exit" | "quit") {
            break;
        }
        let Some(cmd) = args::lookup(first, true) else {
            // A command of the table by its own name, never the word typed:
            // it may be a password (SC2-04).
            let named = args::lookup(first, false).map_or_else(
                || "such command".to_owned(),
                |c| format!("command {}", c.name),
            );
            term::err(&format!(
                "There is no {named} here. Type help to see the commands."
            ));
            continue;
        };
        let rest = &words[1..];
        if cmd.name == "help" {
            let target = rest.first().and_then(|c| args::lookup(c, true));
            print!("{}", target.map_or_else(args::overview, args::command_help));
            continue;
        }
        // `open VAULT` names its vault even while one is open.
        let vault_open = open.is_some() && cmd.name != "open";
        let args::Outcome::Run(p) = args::parse_or_report(cmd, rest, vault_open) else {
            continue;
        };
        match cmd.name {
            "close" => *open = None,
            "open" => {
                *open = None;
                *open = vault::unlock(p.arg(0).unwrap_or(""), &Unlock::of(&p)).ok();
            }
            _ => {
                let _ = commands::run(&p, open);
            }
        }
    }
}

/// INT-10.46: spaces and tabs separate words; a backslash makes the next
/// character literal; a double quote that starts a word, or closes an open
/// quote, groups words; other double quotes and single quotes are literal.
pub fn split(line: &str) -> Vec<String> {
    let mut words = Vec::new();
    let (mut word, mut in_word, mut quoted) = (String::new(), false, false);
    let mut chars = line.chars();
    while let Some(c) = chars.next() {
        match c {
            '\\' => {
                if let Some(next) = chars.next() {
                    word.push(next);
                }
                in_word = true;
            }
            '"' if quoted => quoted = false,
            _ if quoted => word.push(c),
            ' ' | '\t' => {
                if in_word {
                    words.push(std::mem::take(&mut word));
                    in_word = false;
                }
            }
            '"' if !in_word => {
                quoted = true;
                in_word = true;
            }
            _ => {
                word.push(c);
                in_word = true;
            }
        }
    }
    if in_word {
        words.push(word);
    }
    words
}

#[cfg(test)]
mod tests {
    use super::split;

    #[test]
    fn int10_46_line_splitting() {
        assert_eq!(
            split(r#"show "Full demo entry""#),
            ["show", "Full demo entry"]
        );
        assert_eq!(
            split(r"show Full\ demo\ entry"),
            ["show", "Full demo entry"]
        );
        assert_eq!(
            split("show Full demo\tentry"),
            ["show", "Full", "demo", "entry"]
        );
        assert_eq!(
            split(r#"a b"c "d e" 'f g'"#),
            ["a", "b\"c", "d e", "'f", "g'"]
        );
        assert_eq!(split(r#""" x"#), ["", "x"]);
        assert!(split("   ").is_empty());
    }
}
