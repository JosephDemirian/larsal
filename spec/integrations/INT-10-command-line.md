# INT-10 Command line tool commands, with a parity table

Status: reviewed
Epics: E12-S1 (card written in E1-S6); F05 from E14-S2
Parity rows: SR-13, SC-07, SG-06, SD-07, SF-15, SR-05

## What it does

`larsal` is Larsal's command line tool. It works on vault files directly, one command per run: list, show, search, add, edit, move and delete entries and groups; copy a field to the clipboard and clear it later; manage attachments; create a vault, change its credentials, merge two vaults, import a plain XML document, export the vault; print facts about a vault; check passwords against a downloaded list of leaked hashes; make passwords and passphrases; rate a password. The `open` command keeps one vault unlocked for a run of commands typed one per line (the shell).

Every command that needs a vault unlocks it itself: it asks for the password on the terminal without echo, or reads it from standard input when that is a pipe. Nothing secret is printed unless the command asks for it by name or by flag (SR-13). A changing command saves the vault once, at its end, the safe way of APP-05.

The tool is a separate program from the window app. It never talks to a running Larsal (no APP-09 channel), keeps no recent list, offers no quick unlock and never writes Larsal's settings.

Who owns what: entry and group rules MOD-01 to MOD-07; placeholders MOD-08.25; merge MOD-11; search language FEA-01; generator FEA-02; passphrases FEA-03; one-time codes FEA-04; strength FEA-05; breach check FEA-06; statistics FEA-07; import FEA-08.61 and FEA-08.62; export FEA-09; key files FMT-18; cost check CRY-02.14; saving APP-05; clipboard APP-03; unlock error kinds APP-06; hardening and self-test APP-11; key change notices MOD-13.16; hardware keys INT-07 (E10); Larsal's license and notices E14-S2, the word list attribution FEA-03. This card owns the commands, their options, arguments, output, messages and exit codes.

## Inputs and outputs

### Command line syntax

`larsal [TOP-LEVEL FLAG] | larsal COMMAND [OPTIONS] ARGUMENTS`

- Long options take a value as `--name value` or `--name=value`. Short options take it as `-x value` or `-xvalue`. Short flags without a value combine (`-ln`). Options may stand before, between or after the arguments. `--` ends the options; everything after it is an argument. A value option given twice keeps the last value, except `show -a`, which keeps all (INT-10.2).
- Arguments in capitals below. `VAULT` is a vault file path, `ENTRY` an entry path, `GROUP` a group path (INT-10.17, INT-10.18).

### Top-level flags

| ID | Larsal | Reference spelling | Effect |
|---|---|---|---|
| F01 | (none) | same | Usage and the command list on stdout, exit 0 |
| F02 | `-h`, `--help` | same; `--help-all` accepted as an alias (it lists toolkit options in the reference; Larsal has none) | Same as F01 |
| F03 | `-v`, `--version` | same | The version number alone on stdout, exit 0 |
| F04 | `--debug-info` | same | Build and system facts on stdout, exit 0 (INT-10.3) |
| F05 | `--license` | none (Larsal only) | Larsal's license notice and the word list attribution on stdout, exit 0 (INT-10.3, E14-S2) |

### Commands

C01 to C26 run as `larsal COMMAND`. C27 and C28 exist only in the shell. The reference spelling is an accepted hidden alias where it differs (D-INT10-1); aliases are not listed in help.

| ID | Larsal command | Reference spelling | Arguments | One-line help (Larsal) |
|---|---|---|---|---|
| C01 | `add` | same | VAULT ENTRY | Make a new entry. |
| C02 | `analyze` | same | VAULT | Check the passwords against a list of leaked password hashes. |
| C03 | `attachment-export` | same | VAULT ENTRY NAME [FILE] | Write an attachment to a file or to standard output. |
| C04 | `attachment-import` | same | VAULT ENTRY NAME FILE | Attach a file to an entry. |
| C05 | `attachment-rm` | same | VAULT ENTRY NAME | Delete one of an entry's attachments. |
| C06 | `clip` | same | VAULT ENTRY [SECONDS] | Put a field on the clipboard and clear it later. |
| C07 | `close` | same | none | Close the vault open in the shell. |
| C08 | `db-create` | same | VAULT | Make a new, empty vault. |
| C09 | `db-edit` | same | VAULT | Change a vault's password or key file. |
| C10 | `db-info` | same | VAULT | Print facts and counts about a vault. |
| C11 | `passphrase` | `diceware` | none | Make a random passphrase from a word list. |
| C12 | `edit` | same | VAULT ENTRY | Change an entry's fields. |
| C13 | `estimate` | same | none (the reference also takes PASSWORD) | Rate how hard a password is to guess. |
| C14 | `export` | same | VAULT | Print the whole vault, not encrypted, as XML, CSV or HTML. |
| C15 | `generate` | same | none | Make a random password. |
| C16 | `help` | same | [COMMAND] | Show the commands, or one command's options. |
| C17 | `import` | same | XML VAULT | Make a new vault from a plain XML document. |
| C18 | `ls` | same | VAULT [GROUP] | List a group's entries and groups. |
| C19 | `merge` | same | VAULT SOURCE | Bring the changes of another vault into this one. |
| C20 | `mkdir` | same | VAULT GROUP | Make a new group. |
| C21 | `mv` | same | VAULT ENTRY GROUP | Put an entry in a different group. |
| C22 | `open` | same | VAULT | Unlock a vault and keep it open for several commands. |
| C23 | `rm` | same | VAULT ENTRY | Move an entry to the recycle bin, or delete it. |
| C24 | `rmdir` | same | VAULT GROUP | Move a group to the recycle bin, or delete it. |
| C25 | `search` | same | VAULT TERM | Find entries with the search language. |
| C26 | `show` | same | VAULT ENTRY | Print an entry's fields. |
| C27 | `exit` | same | none | Leave the shell. |
| C28 | `quit` | same | none | Leave the shell. |

### Unlock options

Every command that unlocks `VAULT` (C01 to C06, C09, C10, C12, C14, C18 to C26) has these options, plus `-h`, `--help`.

| ID | Larsal option | Reference spelling | Value | Effect |
|---|---|---|---|---|
| U01 | `-k`, `--key-file` | same | path | Key file part of the key (INT-10.13) |
| U02 | `--no-password` | same | none | The key has no password part; no prompt (INT-10.12) |
| U03 | `--hw-key` | `-y`, `--yubikey` | `SLOT[:SERIAL]` | Hardware key part (INT-10.14) |
| U04 | `-q`, `--quiet` | same | none | No prompts, notes or success lines; errors still print (INT-10.7) |
| U05 | `--allow-slow-unlock` | none (Larsal only) | none | Approves a key derivation in the ask band (INT-10.15, D-INT10-6) |

`-q` is also accepted by the commands without a vault (C08, C11, C13, C15, C17).

### Options per command

| Command | Larsal options (reference spelling where it differs) |
|---|---|
| add | `-u`, `--username` TEXT; `--url` TEXT; `--notes` TEXT; `-p`, `--password-prompt`; `-g`, `--generate`; generator options G |
| edit | the options of add, plus `-t`, `--title` TEXT |
| G (generator options, FEA-02.21) | `-L`, `--length` N; `-l`, `--lower`; `-U`, `--upper`; `-n`, `--numeric`; `-s`, `--special`; `-e`, `--extended`; `-x`, `--exclude` CHARS; `-c`, `--custom` CHARS; `--exclude-similar`; `--every-group` |
| generate | G |
| passphrase | `-W`, `--words` N; `-w`, `--word-list` PATH |
| ls | `-R`, `--recursive`; `-f`, `--flatten` |
| show | `-a`, `--attributes` NAME (repeatable); `-s`, `--show-protected`; `--all`; `--show-attachments`; `-t`, `--totp` |
| clip | `-a`, `--attribute` NAME (default `Password`); `-t`, `--totp`; `-b`, `--best-match` |
| analyze | `-H`, `--hash-file` FILE (reference: `-H`, `--hibp`; its `--okon` PATH is not accepted, INT-10.32) |
| estimate | `-a`, `--advanced` |
| export | `-f`, `--format` `xml`, `csv` or `html` |
| db-create, import | `-p`, `--set-password`; `--set-key-file` PATH (reference also `-k` PATH, kept as an alias here only); `-t`, `--decryption-time` MS |
| db-edit | `-p`, `--set-password`; `--set-key-file` PATH; `--unset-password`; `--unset-key-file` |
| merge | `-s`, `--same-credentials`; `--key-file-from` PATH; `--no-password-from`; `--hw-key-from` SLOT[:SERIAL] (reference: `--yubikey-from`); `-d`, `--dry-run` |
| attachment-export | `--stdout`; `-f`, `--force` (Larsal only) |
| attachment-import | `-f`, `--force` |

### Standard streams

- **stdin**: password lines (INT-10.12), the entry password of add and edit `-p`, the password to rate (estimate), y/N answers, and the shell's command lines.
- **stdout**: command data (lists, fields, exports, generated values, attachment bytes) and the success lines.
- **stderr**: every prompt, note, warning and error, and clip's countdown (M10-69).
- Text is UTF-8 with LF line ends. Numbers are plain digits with `.` as the decimal mark, whatever the locale.

### Exit codes

| Situation | Code |
|---|---|
| Success, including help, version, debug info, the license notice, `help` with any argument, `close` outside the shell, a dry run, "nothing changed", analyze with no findings | 0 |
| Any error: usage, unlock, path not found, save failed, search with no result, show or clip with an unknown field, clip of an empty field | 1 |
| A quit signal (SIGINT, SIGTERM, SIGQUIT, SIGHUP) at a prompt, during the clip wait or in the shell | ended by that signal, after the terminal is restored and the clipboard is cleared if still ours (INT-10.12, INT-10.29) |

Larsal never uses 2 or any other code (D-INT10-2).

### Messages

Larsal's own words. `<vault>`, `<path>`, `<file>` are shown as typed. Errors start with `larsal: `.

| ID | Stream | When | Text (Larsal) |
|---|---|---|---|
| M10-01 | stderr | Unknown command | larsal: there is no command <name>. Run larsal help to see the commands. |
| M10-02 | stderr | Unknown option, option without its value, missing or extra argument | larsal <command>: <problem>. Run larsal help <command> to see its options. `<problem>` is one of: unknown option <option>; <option> needs a value; <argument> is missing; unexpected argument <argument>; <value> is not a slot (1 or 2) with an optional serial (for `--hw-key`, INT-07.27, LD-175). |
| M10-03 | stdout | F01, F02 | "Larsal command line tool.", the usage line `Usage: larsal COMMAND [OPTIONS] ARGUMENTS, or larsal -h \| -v \| --license \| --debug-info`, then one line per command: the name and its one-line help |
| M10-10 | stderr | Unlock password prompt | `Vault password for <vault>: ` (no newline; a newline follows the read) |
| M10-11 | stderr | VAULT does not exist | larsal: <vault> does not exist. |
| M10-12 | stderr | VAULT is a folder or special file | larsal: <vault> is not a vault file but a folder or special file. |
| M10-13 | stderr | VAULT cannot be read | larsal: <vault> cannot be read: permission denied. |
| M10-14 | stderr | `--no-password` with no key file and no hardware key | larsal: nothing to unlock <vault> with. --no-password needs --key-file or --hw-key. |
| M10-15 | stderr | Key derivation in the ask band (CRY-02.14) | larsal: unlocking <vault> needs about <memory> of memory and about <time> on this Mac[ and <lanes> parallel lanes]. Nothing was done. Run the command again with --allow-slow-unlock to go ahead. |
| M10-16 | stderr | Key file of an early kind (FMT-18.18) | Note: <keyfile> is an early kind of key file. It works, but a later Larsal may stop reading it. db-edit --set-key-file moves the vault to a new key file. |
| M10-17 | stderr | Vault version above 4.1 (APP-06.21) | Note: <vault> uses a newer vault format than Larsal knows. Saving may lose settings that only the newer format holds. |
| M10-18 | stderr | The hardware key waits for a touch | Touch your security key to go on. |
| M10-20 | stderr | ENTRY not found | larsal: no entry at <path>. |
| M10-21 | stderr | GROUP (or the group part of a path) not found | larsal: no group at <path>. |
| M10-22 | stderr | add: the path already finds an entry | larsal: an entry is already found at <path>. To add one in the root group, start the path with /. |
| M10-23 | stderr | mkdir: the group exists | larsal: a group <path> is already there. |
| M10-24 | stderr | mv: already in that group | larsal: nothing to move: <title> is in <group>. |
| M10-25 | stderr | rmdir of the root group | larsal: the root group belongs to every vault and cannot be removed. |
| M10-26 | stderr | add with an ENTRY that is empty or ends with `/` (LD-172) | larsal: <path> gives no title for the new entry. |
| M10-30 | stderr | edit with nothing to change | larsal: nothing to change in <path>. Give --title, --username, --url, --notes, --password-prompt or --generate. |
| M10-31 | stderr | `-g` with `-p` | larsal: --generate and --password-prompt exclude each other. |
| M10-32 | stderr | Generator options cannot make a password | larsal: <value> is not a usable length. / larsal: these generator options cannot make a password: <reason of FEA-02.5>. |
| M10-33 | stderr | add `-p` prompt | `Entry password: ` |
| M10-34 | stderr | edit `-p` prompt | `New entry password: ` |
| M10-35 | stderr | passphrase: bad word count | larsal: <value> is not a usable word count. |
| M10-40 | stdout | add done | New entry <title> saved. |
| M10-41 | stdout | edit done | Changes to <title> saved. |
| M10-42 | stdout | mkdir done | New group <name> saved. |
| M10-43 | stdout | mv done | <title> moved to <group>. |
| M10-44 | stdout | rm done | <title> moved to the recycle bin. / <title> deleted for good. |
| M10-45 | stdout | rmdir done | Group <path> moved to the recycle bin. / Group <path> deleted for good. |
| M10-46 | stdout | attachment-import done | <file> attached to <entry> as <name>. |
| M10-47 | stdout | attachment-export to a file done | Attachment <name> of <entry> written to <file>. |
| M10-48 | stdout | attachment-rm done | Attachment <name> removed from <entry>. |
| M10-49 | stdout | db-create, import: the key derivation was tuned | Key derivation tuned to about <ms> ms on this Mac: <count> iterations. ("rounds" for AES-KDF) |
| M10-50 | stdout | db-create done; import done | New vault <vault> saved. / New vault <vault> made from <xml>. |
| M10-51 | stdout | db-edit | New credentials of <vault> saved. / Nothing changed; <vault> was not saved. |
| M10-52 | stdout | merge | <target> saved with the changes from <source>. / <target> is unchanged. |
| M10-55 | stderr | No attachment of that name | larsal: <entry> has no attachment called <name>. |
| M10-56 | stderr | attachment-import over an existing name | larsal: <entry> already has an attachment called <name>. Add --force to replace it. |
| M10-57 | stderr | A file to read cannot be read | larsal: cannot read <file>: <reason>. |
| M10-58 | stderr | attachment-export with no target | larsal: say where the attachment goes: a file path or --stdout. |
| M10-59 | stderr | attachment-export to an existing file | Question, terminal only: `<file> exists. Replace it? [y/N] ` / refusal: larsal: <file> exists and was left alone. Add --force to replace it. |
| M10-60 | stderr | A file cannot be written | larsal: cannot write <file>: <reason>. |
| M10-61 | stderr | clip: bad SECONDS | larsal: <value> is not a number of seconds (0 or more). |
| M10-62 | stderr | clip: `-a` with `-t` | larsal: --attribute and --totp exclude each other. |
| M10-63 | stderr | show, clip: no such field | larsal: <entry> has no field called <name>. |
| M10-64 | stderr | show, clip: name matches several fields | larsal: <name> could mean any of <list>. Give the exact name. |
| M10-65 | stderr | No one-time password | larsal: <entry> has no one-time password. |
| M10-66 | stderr | clip `-b`: several matches | larsal: <n> entries match <term>: then one path per line |
| M10-67 | stdout | clip `-b`: one match | Best match: <path>. |
| M10-68 | stdout | clip: copied | <field> of <entry> copied. The clipboard is emptied in <n> seconds. / with 0: <field> of <entry> copied. The clipboard is not emptied. |
| M10-69 | stderr | clip: countdown, only when stderr is a terminal and not with `-q`, one line rewritten each second | <n> s left before the clipboard is emptied |
| M10-70 | stdout | clip: wait over | The clipboard is empty again. / The clipboard holds something else now and was left as it is. |
| M10-71 | stderr | clip: the pasteboard refused the write | larsal: could not put the value on the clipboard. |
| M10-98 | stderr | clip: the field's value is empty (INT-10.29, APP-03.5) | larsal: <field> of <entry> is empty. Nothing to copy. |
| M10-72 | stderr | search: no result | larsal: no entry matches <term>. |
| M10-75 | stderr | db-create, import: target exists | larsal: <path> is taken: a file is already there. |
| M10-76 | stderr | db-create, import: no key part chosen | larsal: a vault needs a password, a key file or both. Give --set-password, --set-key-file or both. |
| M10-77 | stderr | `-t` bad | larsal: <value> is not a whole number of milliseconds. / larsal: the unlock time must be 100 to 5000 ms. |
| M10-78 | stderr | New password prompts | `Password for the new vault (Return for none): ` then `Same password again: `; after an empty first line: `Use an empty password? [y/N] ` |
| M10-79 | stderr | Repeat differs; empty password declined | larsal: the two passwords are not the same. Nothing was changed. / larsal: no password chosen. Nothing was changed. |
| M10-80 | stderr | Key file to set cannot be made or read | larsal: cannot use <keyfile> as a key file: <APP-06 key file reason> |
| M10-82 | stderr | db-edit: set and unset together | larsal: <option> and <option> exclude each other. |
| M10-83 | stderr | db-edit: unset a part that is missing | larsal: <vault> has no password to remove. / larsal: <vault> has no key file to remove. |
| M10-84 | stderr | db-edit: no key part would be left | larsal: this would leave <vault> with no key part at all. Nothing was changed. |
| M10-85 | stderr | analyze without the hash list | larsal: give the list of leaked hashes with --hash-file FILE. |
| M10-86 | stdout | analyze: before the findings | Checking every password against <file>. This can need minutes for a big list. |
| M10-87 | stdout | analyze: one finding (FEA-06.20) | Leaked password: <path> (in the list <n> times) / (in the list once) / count 0: Leaked password: <path> |
| M10-88 | stderr | export, every time, also with `-q` (LD-42) | Warning: this export is not encrypted. Anyone who can read it can read every password in it. CSV adds the sentence of LD-43 about values that start with `=`, `+`, `-` or `@`. |
| M10-89 | stderr | export: XML could not be made | larsal: the export failed: <reason>. |
| M10-90 | stderr | Save failed | larsal: could not save <vault>: <reason>. The file on disk is unchanged. |
| M10-91 | stderr | Pre-save check found a change (APP-05.10) | larsal: <vault> changed on disk while this command ran. Nothing was saved; run the command again. |
| M10-92 | stderr | estimate got a password argument | larsal: estimate does not take the password as an argument, because other programs can read arguments. Pipe it in, or type it at the prompt. |
| M10-93 | stderr | estimate prompt, terminal only | `Password to rate: ` |
| M10-94 | stdout | estimate result | `Characters <n>`, TAB, `Bits <e>`, TAB, `Log10 <g>` |
| M10-95 | stderr | Shell: unknown command | There is no command <name> here. Type help to see the commands. |
| M10-96 | stderr | Shell prompt (terminal only) | `larsal (<name>)> `, where <name> is the vault name, or its file name when the name is empty; `larsal> ` with no vault open |
| M10-97 | stderr | merge `-s`: the source does not open with the target's key | larsal: cannot open <source> with the credentials of <target>: <APP-06 text> |

Messages owned elsewhere and used here: M11-02 (self-test, APP-11); the unlock error texts M06-01 to M06-26 and M06-30, printed after `larsal: ` (APP-06); `keychange.msg.cli_forced` and `keychange.msg.cli_recommended` (MOD-13.16); MSG-XML-EXISTS, -NOKEY, -PROTECTED, -NOROOT (FEA-08); MSG-EXP-FORMAT (FEA-09); MSG-BREACH-FILE-PARSE (FEA-06.15); MSG-PP-LIST-SMALL, MSG-PP-LIST-EMPTY, MSG-PP-LIST-UNREADABLE (FEA-03).

Fixed words in data output: `(hidden)` for a protected value (show), `(empty group)` for a group with nothing in it (ls), `Attached files:` and `No attached files.` (show). Field names (`Title`, `UserName`, `Password`, `URL`, `Notes`, `Uuid`, `Tags`) are the file's field keys, not prose.

Messages are in the language of setting S-UI-01 (APP-01); this card gives the English text.

## Rules

### General

INT-10.1 **Start-up order.** (1) Process hardening (APP-11.1: before reading arguments, stdin, settings or files). (2) Read the two settings of INT-10.9, read only. (3) Parse the arguments; a usage error prints M10-02 or M10-01 and exits 1. (4) F01 to F05 and `help` print and exit 0. (5) Crypto self-test (APP-11.10); a failure prints M11-02 and exits 1 before any prompt. (6) Check the command's options and arguments (INT-10.5). (7) Run the command. Release builds install the zeroing allocator (LD-133). Reference: self-test first, then settings, then the arguments; its hardening comes after the self-test (APP-11.1).

INT-10.2 **Syntax.** As in "Command line syntax" above. Same as the reference (its option parser has the same forms).

INT-10.3 **Help, version, debug info, license.** F01 and F02 print M10-03 (aliases not shown). F03 prints only the version number, as the reference does, so scripts can read it. F04 prints the lines of APP-09.4 for the `larsal` binary (product and version, build type, revision, OS, CPU, kernel, features built in, crypto crates and versions) and never a path, setting or vault value. F05 prints Larsal's current source-available license notice (LD-345), fixed text with no path of this Mac, no setting and no vault value, in this order: `Larsal command line tool <version>`; `Copyright (C) 2026 Joseph Demirian`; `Larsal Source-Available License 1.0`; `You may inspect, download, build and run unmodified copies under LICENSE.`; `Modification, resale and using this code in a competing product require`; `separate written permission. Third-party components retain their own rights.`; `There is NO WARRANTY, to the extent permitted by law.`; an empty line; `LICENSE and THIRD-PARTY-NOTICES.md ship in Larsal.app/Contents/Resources`; `and beside this tool in a release folder.`; an empty line; the built-in word list's attribution, the one text `larsal_core::generator::wordlist::ATTRIBUTION` of FEA-03, word for word. F05 is Larsal's own flag: the usage line of M10-03 names it, and F03 is unchanged (the version number alone). `larsal COMMAND -h` (or `--help`) prints that command's usage, options and arguments on stdout and exits 0, whatever valid options come before it; an unknown option earlier on the line is reported first (M10-02), as the standard option parser reads left to right (LD-180). Reference: a command's help goes to stderr with exit 1, and a missing argument is reported first (observed: `ls --help` gave the missing-argument error).

INT-10.4 **Commands and aliases.** The commands are exactly C01 to C26 outside the shell and C01 to C13, C15, C16, C18 to C28 inside it (INT-10.45). The reference spellings `diceware`, `--hibp`, `-y`, `--yubikey`, `--yubikey-from`, and `-k` as the key file to set in db-create and import, work as hidden aliases (D-INT10-1). Anything else is M10-01 (command) or M10-02 (option), exit 1. An unknown top-level option with no command (`larsal --bogus`) is M10-02 without a command name (`larsal: unknown option --bogus. Run larsal help to see the commands.`), exit 1; the reference prints its usage on stdout and exits 0 (observed).

INT-10.5 **Options are checked before any password is read.** Usage, conflicting options (M10-31, M10-62, M10-82), edit with nothing to change (M10-30), generator options (M10-32), SECONDS (M10-61), `-t` (M10-77), a missing `--hash-file` (M10-85), an existing target file (M10-75) and a password argument to estimate (M10-92) are all reported before the first prompt. Reference: several of these come after the unlock, so the user types the password for nothing.

INT-10.6 **Streams.** stdout carries only data and success lines; every prompt goes to stderr. Reference: the unlock prompt goes to stderr, but the entry password prompts of add and edit and the shell prompt go to stdout (observed; the shell prompt also shows when stdin is a pipe). A prompt is written even when stdin is not a terminal, unless `-q` is given (parity), except M10-93 and M10-96, which only appear on a terminal.

INT-10.7 **Quiet.** `-q` drops prompts, notes (M10-16, M10-17, MOD-13.16), info lines (M10-86) and success lines. It never drops an error, the export warning M10-88 or requested data (for example attachment bytes with `--stdout`). With `-q`, merge prints no change lines and no M10-52 (parity). Reference: `-q` also hides every unlock error, so a wrong password exits 1 with no output (observed), and clip's field-not-found error; it does not hide the analyze info line, the success lines of mv and db-edit (observed) or the new-password prompts of db-create, import and db-edit `-p` (source) (D-INT10-3).

INT-10.8 **Exit codes.** As in the table. The option parser's own code for usage errors is replaced by 1 (D-INT10-2).

INT-10.9 **Settings and other state.** The tool reads S-UI-01 (language) and the key derivation speed record of CRY-02.14 from Larsal's settings, read only (D-INT10-6). It writes no setting, keeps no recent list, no shell history and no log of commands, never uses quick unlock (APP-04) and never contacts a running Larsal. A vault open in Larsal and changed by `larsal` is a change on disk for Larsal (APP-05). Reference: reads only its language setting.

INT-10.10 **Vault text on a terminal.** When stdout or stderr is a terminal, every control character from vault text (C0 except TAB and LF, DEL, C1) is printed as a visible escape (`\x1b`, `\x7f`, `\u{9b}`), so a hostile vault cannot drive the terminal. Written to a pipe or a file, vault text is exact. The clipboard always gets the exact value (D-INT10-7). Reference: always exact.

### Unlocking

INT-10.11 **Vault argument checks.** Before any prompt: VAULT must exist (else M10-11), be a regular file after following links (else M10-12) and be readable (else M10-13); exit 1. Same order as the reference.

INT-10.12 **The password.** Unless `--no-password` is given:
1. Print M10-10 on stderr (not with `-q`).
2. If stdin is a terminal, turn its echo off; read one line; turn echo back on; print a newline on stderr (not with `-q`). Otherwise read one line from stdin.
3. The line end (LF or CR LF) is removed; nothing else is trimmed. End of input gives an empty line.
4. The line, empty or not, is the password part of the key. An empty line is an empty password, not "no password", as in the reference (vaults it made with an empty line need it). This differs from the window app's `--password-stdin`, where an empty line means no password part (APP-09.16).
5. A quit signal while echo is off restores the terminal first; then the process ends by that signal (as readpassphrase does; LD-165). Reference: echo stays off after SIGINT at the prompt (observed).
With `--no-password` no line is read and the key has no password part; with no key file and no hardware key either, M10-14, exit 1 (the reference tries an empty key and reports wrong credentials, observed). Commands that read more lines read them in this order: unlock password, then the source password (merge), then the new vault password and its repeat (db-create, import, db-edit `-p`), then the entry password (add, edit `-p`).

INT-10.13 **Key file.** U01 is read after the password line, with the rules of FMT-18. A key file of an early kind prints M10-16 and works. A key file with the same canonical path as VAULT is refused with M06-30's text before any work (FMT-18.24); the reference has no such check and reports wrong credentials (observed). Errors print the APP-06 key file text (M06-07 to M06-16) and exit 1.

INT-10.14 **Hardware key.** U03 adds a challenge-response part, slot 1 or 2, optionally with the key's serial; any other slot or a serial that is not a number is M10-02, exit 1. While the key waits for a touch, M10-18 is printed. Errors print the APP-06 hardware key texts (M06-17 to M06-20). INT-07 owns the challenge; built with E10. Same as the reference.

INT-10.15 **Opening.** The open runs in the order of FMT-05.7 (version 4) or FMT-05.13 (version 3). A failure prints `larsal: ` plus the APP-06 text of its error kind (M06-01 to M06-26) and exits 1. When the cost check of CRY-02.14 asks, the tool runs no key derivation: without U05 it prints M10-15 and exits 1; with U05 it opens with the approval (D-INT10-6). A refusal (`TooLarge`) cannot be approved. When the speed record is missing, the tool measures it in memory as CRY-02.14 describes and does not store it. A file of version 4.2 or later prints M10-17 and goes on. After a successful open, MOD-13.16 applies.

INT-10.16 **Secrets.** Passwords read, the composite key, protected values and generated values live only in Larsal's secret types (APP-11.9) and are wiped before exit. No option or environment variable takes a password or other secret (SR-13); estimate reads its password from stdin only (D-INT10-4). No error, note or log line holds a secret. Generated passwords for add and edit `-g` are never printed.

### Paths

INT-10.17 **Entry paths.** A path that holds no `/` finds the first entry with exactly that title anywhere in the vault, in tree order (a group's own entries before its subgroups, groups in stored order). A path with a `/` names the entry from the root group: group names below the root, then the title, joined by `/`; a leading `/` is optional. Matching is exact: case-sensitive, no Unicode normalization. Entries in the recycle bin are found like any other (`Recycle Bin/<title>`). A path with `/` is compared as one string with `/` + group names + `/` + title, so a title or group name that holds `/` makes paths ambiguous (MOD-02.3): `a/b` finds an entry titled `a/b` in the root group and entry `b` in group `a` alike, and the first in tree order wins. An entry with an empty title in group `G` is found by `G/` (in the root group by `/`). Same as the reference (observed: a root entry retitled `Work/Servers/Server login` was found by that path before the real one; `/` found rich-v3's untitled root entry).

INT-10.18 **Group paths.** Empty, `/`, or nothing given (ls) is the root group. Otherwise group names below the root joined by `/`, with an optional leading and trailing `/`. Exact matching, first match in tree order. Same as the reference, except that mkdir also accepts a trailing `/` (INT-10.23).

INT-10.19 **Paths in output.** search, clip `-b` and M10-66 print `/` + the group names below the root + `/` + the title (an entry in the root group: `/<title>`). analyze prints the form of FEA-06.20, without the leading `/`. Same as the reference.

### Saving

INT-10.20 **How a changing command saves.** add, edit, mkdir, mv, rm, rmdir, attachment-import, attachment-rm, db-edit (with a key change) and merge (with changes, not a dry run) save once, after the whole change, with APP-05.9 to APP-05.12: real path through links, the pre-save check, the safe save, permission bits kept. No backup is made and no watcher runs (APP-05). The command saves even when the new values equal the old ones, as the reference does (no history item then, MOD-03.2). The pre-save check finding a change prints M10-91; any other failure prints M10-90; both exit 1 and leave the file as it was. db-create and import write a new file with mode 0600 (APP-05.12) and never replace an existing one. The version written follows FMT-16.

### Commands

INT-10.21 **add.** Makes an entry whose title is the last part of ENTRY, in the group named by the rest (the root group when ENTRY has no `/`). It refuses when ENTRY already finds an entry (INT-10.17: with no `/`, any entry with that title anywhere; M10-22) or the group does not exist (M10-21). `--username`, `--url` and `--notes` set their fields when the value is not empty; in `--notes` each two-character sequence `\n` becomes a line feed. `-p` reads the entry password (M10-33, INT-10.12 steps 2, 3 and 5); `-g` sets a password made by FEA-02 with the generator options (FEA-02.21). The new entry has the defaults of MOD-01 and no default user name (MOD-01.22). Success: M10-40. Same as the reference.

INT-10.22 **edit.** Changes the fields given (`--title` too) in one edit session (MOD-03.4). An option with an empty value counts as not given, so a field cannot be emptied from the command line (parity). With no field, `-p` or `-g` given: M10-30, exit 1. Success: M10-41 with the new title. History follows MOD-03.2. Same as the reference.

INT-10.23 **mkdir.** Makes a group named by the last part of GROUP in the group named by the rest, with the defaults of MOD-02.7. One trailing `/` is ignored first. Refuses an existing group (M10-23) and a missing parent (M10-21). Success: M10-42. Reference: the same, but a trailing `/` makes the name empty and the parent lookup fail (observed: `/Top/` reported its parent missing).

INT-10.24 **mv.** Moves the entry into GROUP (MOD-02 moves, times as there). Same group: M10-24. Missing entry or group: M10-20 or M10-21. No history item (MOD-03.5, L03-1); the reference makes one (MOD-03 case 03-07). Success: M10-43.

INT-10.25 **rm.** With the recycle bin on (MOD-04) and the entry outside the bin, the entry goes to the bin (made first if missing, MOD-04); otherwise it is deleted for good and recorded as deleted (MOD-04.4, FMT-15). Success: M10-44 naming which happened. Same as the reference.

INT-10.26 **rmdir.** The root group is refused (M10-25, also for an empty GROUP). Otherwise as rm, for the group and everything in it. A group that holds the recycle bin is deleted for good with all it holds (MOD-04.4); the installed reference hangs and leaves the file unchanged (MOD-04 case 04-09). Success: M10-45.

INT-10.27 **ls.** Lists GROUP (default root): first its entries' titles in stored order, then its child groups as `<name>/`. `-R` lists each child group's content right after its line, indented by two spaces per level. `-f` prefixes every line with the path of its group relative to GROUP (`Servers/Old servers/Old server`) instead of indenting. A group with no entries and no groups prints `(empty group)` (with `-f`, after the prefix). Titles print raw (MOD-08.25); an empty title prints an empty line. The recycle bin is listed like any group. Same as the reference, apart from the marker word.

INT-10.28 **show.**
- No `-a`, no `--all`, no `-t`: seven lines `Title: `, `UserName: `, `Password: `, `URL: `, `Notes: `, `Uuid: `, `Tags: ` with values. A protected value prints `(hidden)` unless `-s` is given.
- `--all`: the same seven lines, then every other field sorted by name in UTF-16 code unit order (capitals before small letters: `Demo PIN` before `Demo hint`, `otp` last), as the reference does, as `<name>: <value>`, protected ones `(hidden)` unless `-s`. Passkey fields are included (INT-04.55).
- `-a NAME` (repeatable): each value alone on its own line, in the order given, protected or not: naming a field is asking for it (SR-13). `Uuid` and `Tags` match only with that exact case. Other names match a field exactly; else the fields whose names equal NAME ignoring case: none gives M10-63, more than one gives M10-64. Such an error is printed and the next name is handled; the exit code is then 1.
- Values are resolved (MOD-08.25); multi-line values print as they are. `Uuid` is the entry id as lowercase hex with dashes in braces (`{00000000-0000-0000-0000-00000000000a}`). `Tags` is the tag list joined by `,` (MOD-07).
- `--show-attachments`: after the fields, an empty line, then `Attached files:` and one line per attachment sorted by name, `  <name> (<size>)`, or `No attached files.`. Size: under 1,024 bytes `<n> B`; else KiB, MiB or GiB with one decimal.
- `-t`: the current one-time code (FEA-04) as the last line; with neither `-a` nor `--all` it is the only line. An entry without one: M10-65, exit 1, nothing printed.
- Same as the reference, apart from the marker and attachment words.

INT-10.29 **clip** (SC-07).
- The field: `-a NAME` (default `Password`), matched as in show; `Uuid` and `Tags` allowed; `-t` or `-a totp` (exact) take the current one-time code (M10-65 when none). `-a` with `-t`: M10-62 before the unlock. The value is raw, not resolved (MOD-08.25).
- `-b`: ENTRY is a search term; the tool searches `title:<term>` with INT-10.30's scope. One result: M10-67, use it. Several: M10-66 on stderr, exit 1, nothing copied. None: ENTRY is used as a path.
- An empty value copies nothing, as APP-03.5 rules for Larsal: the pasteboard is left untouched, no wait starts, M10-98 on stderr, exit 1 (Decided: spec/decisions.md LD-168 D-A03-1, LD-200 (8)).
- The copy goes through Larsal's copy routine (APP-03.2): concealed and transient markers (APP-03.9) and the change count (APP-03.10). M10-68 follows.
- SECONDS: a whole number 0 to 2,147,483,647, default 10; anything else M10-61. 0: the tool exits at once and nothing clears the value. Otherwise the tool waits; when stderr is a terminal, M10-69 counts down there. At the end it empties the pasteboard only if the change count still matches (APP-03.12) and prints M10-70 either way; exit 0.
- A quit signal during the wait runs the same clear at once, then the process ends by that signal.
- Reference (APP-03.20): copies through the system's plain copy program with no markers, and after the wait empties the clipboard without checking it; a signal ends it with the value left on the clipboard (source: no signal handling). Its "field not found" message goes to stdout (observed) and its countdown goes to stdout even when that is not a terminal (source); Larsal's M10-63 and M10-69 go to stderr.

INT-10.30 **search.** TERM is a query in the FEA-01 language. Scope: the whole vault, ignoring group search flags (FEA-01.20), but never the recycle bin or anything in it (LD-57, D-INT10-11), never history. Results print one path per line (INT-10.19) in FEA-01's result order. No result: M10-72, exit 1. Reference: also lists recycle bin entries (observed: `deleted` listed both demo entries in the bin).

INT-10.31 **db-info.** Prints `<label>: <value>` lines, in this order, values from the one computation of FEA-07.21: Name, Description, Cipher (`AES-256`, `ChaCha20` or `Twofish`), Key derivation (for example `Argon2id, 64 MiB, 10 iterations, 4 lanes` or `AES-KDF, 1000000 rounds`), Recycle bin (`on` or `off`), File (VAULT as typed), Created on, Most recent save, Changes not saved yet (`no`), then the counts with the FEA-07 labels in the reference's order: Groups, Entries, Past expiry, Different passwords, Repeated passwords, Most uses of one password, Under 8 characters, Rated below Good, Skipped in reports, Length on average (`1 character`, `N characters`), Passkey entries, One-time code entries. Times are RFC 3339 in the Mac's local time zone, for example `2024-01-01T01:00:00+01:00` (D-INT10-10; FEA-07.20). Reference: also prints an id that is made fresh at every open (observed: two runs gave two ids), which Larsal leaves out; its times use the locale's short form, and the creation time is shown in UTC as if it were local (FEA-07.20); the installed 2.7.11 prints no passkey and one-time code rows (the source does).

INT-10.32 **analyze** (SG-06). `--hash-file FILE` is required (M10-85, before the unlock). An unreadable FILE prints M10-57 after the unlock. Then M10-86, the offline check of FEA-06.14 to FEA-06.20 (streamed, findings in file order), one M10-87 line per finding; exit 0, also with none. A parse error prints MSG-BREACH-FILE-PARSE and exits 1. Larsal does not hand hashes to an outside program, so the reference's option for one is not accepted (FEA-06.21, D-06-10).

INT-10.33 **estimate.** Reads one line from stdin (on a terminal: M10-93, echo off, INT-10.12 steps 2, 3 and 5). A PASSWORD argument is refused with M10-92 (D-INT10-4). Prints M10-94: `<n>` is the number of characters (Unicode scalar values), `<e>` is E of FEA-05.1 and FEA-05.2 with 3 decimals, `<g>` is E × log10(2) with 3 decimals. An empty line gives `Characters 0`, `Bits 0.000`, `Log10 0.000`. `-a` adds one line per match of the estimator's match sequence, in password order: the match kind, the part of the password it covers, and its bits with 3 decimals; the user typed that password, so printing its parts is asked for. Reference: takes the password as an argument or reads it with echo on (observed), counts its length in UTF-8 bytes (observed: `é` gave 2), and its estimator's numbers can differ (FEA-05.1, FEA-05.19).

INT-10.34 **generate.** One password made by FEA-02 from the options (FEA-02.21; FEA-02.11: the saved settings are ignored), printed on stdout with a line feed. Length 1 to 10,000 (D-02-4). Invalid options: M10-32, exit 1. Same as the reference, apart from D-02-1 and the length limit (the reference takes up to 2^31 − 1).

INT-10.35 **passphrase.** One passphrase made by FEA-03.16 (`-W` default 7, `-w` default the built-in list), printed with a line feed. A word count that is not a whole number from 1 to 1,000 (D-03-5): M10-35, exit 1, before any output (the reference has no upper limit). The small-list warning goes to stderr (FEA-03.12); an empty or unreadable list is an error, exit 1 (D-03-4); the reference prints an empty line and exits 0.

INT-10.36 **export.** Writes the vault in the chosen format to stdout (FEA-09.16): `xml` (also when `-f` is missing or empty), `csv` or `html`, matched exactly, ignoring case (D-INT10-5). Any other value: MSG-EXP-FORMAT, exit 1. Before the data, M10-88 on stderr, every time (LD-42). Reference: no warning; matches by prefix, so `XMLX` gives XML (FEA-09.16). Not available in the shell.

INT-10.37 **import.** Makes a new vault at VAULT from the XML document (FEA-08.61, FEA-08.62), with the key parts of db-create (INT-10.38 steps 1 to 4), then writes it (INT-10.20). The target must not exist (MSG-XML-EXISTS, before any prompt); no key part chosen gives MSG-XML-NOKEY before the document is read. Document errors: the FEA-08 messages; nothing is written. Success: M10-50. Not available in the shell.

INT-10.38 **db-create.**
1. VAULT must not exist (M10-75); `-t` must be a whole number of 100 to 5,000 (M10-77). Both before any prompt.
2. `-p`: M10-78; an empty first line asks the empty-password question (y or Y as the first character means yes; anything else no, M10-79). A non-empty first line needs the same second line (else M10-79). Echo is off for both password lines on a terminal.
3. `--set-key-file PATH`: an existing file is read as the key file (FMT-18) and left unchanged; a missing one is created as XML 2.0 with mode 0400 (FMT-18.20 to FMT-18.22). Errors: M10-80. The path equal to VAULT is refused (FMT-18.24).
4. Neither part: M10-76, nothing created.
5. The vault holds what APP-07.19 lists (root group `Root`, recycle bin on, MOD-12.22 values; vault name empty), with CRY-02.23's defaults (AES-256, Argon2id, 64 MiB) and iterations from Larsal's benchmark (CRY-02.28) for `-t` or 1,000 ms (D-INT10-9). With `-t`, M10-49. Success: M10-50.
Reference: AES-KDF, version 3.1, a fixed 1,000,000 rounds when `-t` is missing (CRY-02.22), root group named with its word for "Passwords" (MOD-02.2); a missing key file is created as 128 random bytes unless the name ends with its XML key file extension (FMT-18.21).

INT-10.39 **db-edit.** Changes the key parts: `-p` sets a new password (INT-10.38 step 2); `--set-key-file` sets a key file (INT-10.38 step 3); `--unset-password` and `--unset-key-file` remove a part. A hardware key part is kept. Set and unset of the same part together: M10-82. Unset of a missing part: M10-83. No part left: M10-84. Conflicts are found before the unlock; missing parts after it. No key option: M10-51 "nothing changed", exit 0, no save. A change saves (INT-10.20) and counts as a key change (MOD-13.11). Same as the reference, apart from the key file kind it creates.

INT-10.40 **merge.** VAULT is the target and SOURCE the source (MOD-11.28). The source unlocks with `--key-file-from`, `--no-password-from` and `--hw-key-from` and its own password line, or with `-s` with the target's key (M10-97 on failure). The merge follows MOD-11; each change prints one line on stdout in the text form of MOD-11.24 (TAB first), with no values (D-11-10); `-q` drops them (INT-10.7). With changes and no `-d`: save (INT-10.20), then M10-52 (saved). Otherwise M10-52 (unchanged). Exit 0. The tool keeps no retired-key records and makes no MOD-11.31 check: the records are Larsal's local state, never synced, and a tool merge is one the user starts by naming the file and typing its credentials (decided: spec/decisions.md LD-283 (4)). Reference: the same flow; its change lines can hold custom data values (MOD-11.24).

INT-10.41 **attachment-export.** `--stdout` writes the attachment's exact bytes to stdout, also with `-q`, and no success line. Else FILE is required (M10-58). A new FILE is written with mode 0600 (SD-09). An existing FILE: with `-f` it is replaced; without, on a terminal M10-59 asks (default No); when stdin is not a terminal, `-q` is given or the answer is No, M10-59's refusal, exit 1, file untouched (MOD-05.15, L05-5). Write errors: M10-60. Success: M10-47. Never changes the vault. Reference: no `-f`; overwrites silently with default permissions (MOD-05 case 05-23).

INT-10.42 **attachment-import.** An existing NAME needs `-f` (M10-56); this is checked before FILE is read, as in the reference. Then reads FILE (M10-57 when it cannot) and sets attachment NAME of the entry in one edit session (MOD-03.4). Saves; success M10-46. Same as the reference.

INT-10.43 **attachment-rm.** Removes attachment NAME (M10-55 when missing) in one edit session. Saves; success M10-48. Same as the reference.

INT-10.44 **help and close.** `help` prints M10-03; `help COMMAND` prints that command's help; an unknown COMMAND prints M10-03. All on stdout, exit 0. Outside the shell, `close` does nothing and exits 0. Same as the reference.

### The shell

INT-10.45 **open.** Unlocks VAULT (INT-10.11 to INT-10.15); a failure exits 1. Then it reads command lines from stdin, one at a time, until `exit`, `quit` or end of input, and exits 0. On a terminal it prints M10-96 before each line. While a vault is open, the commands that unlock VAULT act on it and take no VAULT argument; with no vault open they take VAULT as outside the shell. The other commands are unchanged. `export` and `import` are not shell commands (M10-95). Each changing command saves at once (INT-10.20). `close` closes the vault (wiped). `open VAULT` inside the shell first closes the current vault, then unlocks the new one; on failure no vault is open. Errors do not end the shell. Lines are read one at a time, so piped input works: `printf 'pw\nls\n' | larsal open v` lists v. Reference: piped input is lost after the password (observed: nothing after the first prompt); it keeps an in-memory line history with line editing (D-INT10-8).

INT-10.46 **Shell line splitting.** Spaces and tabs separate words. A backslash makes the next character literal. A double quote that starts a word, or closes an open quote, groups words; other double quotes are literal. Single quotes are literal. An empty line does nothing. Same as the reference.

INT-10.47 **Leaving the shell.** `exit`, `quit` and end of input close the vault (wiped) and exit 0. A quit signal closes the vault and ends the process by that signal, terminal restored. The vault stays unlocked while the shell runs; there is no idle close (as the reference; D-INT10-8).

## Edge cases and errors

- **Title-only path matches a deeper entry** (`add v "Server login"` while `Work/Servers/Server login` exists): M10-22; `add v "/Server login"` adds it in the root group. Same in the reference (observed).
- **Two entries with the same path:** the first in tree order wins for every command (INT-10.17).
- **Empty title:** an empty ENTRY is never a match; an untitled entry is reached by its group path with a trailing `/` (`G/`, or `/` in the root group; INT-10.17) and shows as an empty line in ls.
- **edit `-u ""`:** ignored, the field keeps its value (INT-10.22).
- **show and clip on a recycled entry:** allowed by path (`Recycle Bin/<title>`), while search never lists it.
- **merge where SOURCE is VAULT:** opens the same file twice; nothing changes (MOD-11.30); exit 0.
- **Vault changed by Larsal while `larsal` runs:** M10-91, nothing saved (INT-10.20).
- **Key file path equal to VAULT in db-create or db-edit:** refused (FMT-18.24).
- **db-create where the key file path is a folder:** M10-80 with the M06-14 reason, nothing created.
- **`-t 99`, `-t 5001`, `-t abc`, `-t 0`:** M10-77 before any prompt (CRY-02.26 limits kept).
- **clip with a negative SECONDS:** the parser reads `-5` as an option, M10-02 (same in the reference).
- **clip of an empty value:** nothing copied, the pasteboard left as it was, M10-98, exit 1 (INT-10.29, APP-03.5, LD-200 (8)). The reference copies an empty string, which wipes what the user had on the clipboard.
- **show `-s -a Password`:** the same as `-a Password`.
- **Version 1 files:** M06-02's text; the command line has no import for them (FEA-08 owns that import in the window).
- **Placeholder names:** the window binary `Larsal` and the tool `larsal` cannot sit in one folder on a case-insensitive volume. Where `larsal` lives in the bundle and how it reaches the PATH is E14's packaging question; the rename (D1) may remove the clash.
- **Shell on a vault whose name holds control characters:** the prompt shows them escaped (INT-10.10).

### Lead decisions

Decided: spec/decisions.md LD-171; review findings R10-1 to R10-4: LD-172 (all eleven as recommended).

- **D-INT10-1 Reference spellings.** (a) Accept them as hidden aliases (INT-10.4); (b) Larsal names only. Recommend (a): scripts written for the reference keep working, as APP-09 did with D-APP09-1.
- **D-INT10-2 Exit codes.** (a) 0 and 1 only, as the reference; (b) 2 for usage errors, the option parser's default. Recommend (a): Verify compares exit codes and scripts expect the reference's.
- **D-INT10-3 Quiet and errors.** (a) `-q` never hides an error (INT-10.7); (b) as the reference, which hides unlock errors too. Recommend (a): a silent failure with exit 1 hides a wrong password from the user.
- **D-INT10-4 estimate and its argument.** (a) Accept the password as an argument, as the reference; (b) refuse it, stdin only (INT-10.33); (c) accept it with a warning. Recommend (b): arguments show in the process list and shell history (SR-13, APP-09.18); the warning in (c) comes after the leak.
- **D-INT10-5 Export format names.** (a) Exact names, ignoring case, as built (LD-143 (10)); (b) prefix matching as the reference. Recommend (a): `XMLX` giving XML is an accident, and the code already does (a).
- **D-INT10-6 Slow unlock from the command line** (CRY-02.14 leaves it to this card). (a) Stop with M10-15, approve with `--allow-slow-unlock`; read the speed record from Larsal's settings, read only, else measure it in memory; (b) ask y/N on a terminal and refuse on a pipe; (c) no check in the tool. Recommend (a): scripts get a clear, repeatable answer, and the flag makes the approval explicit. This adds the speed record to what the tool reads; APP-01 says the tool reads only the language, so APP-01 needs that line changed.
- **D-INT10-7 Control characters on a terminal.** (a) Escape them when the stream is a terminal, exact otherwise (INT-10.10); (b) always exact, as the reference. Recommend (a): a vault is hostile input, and escape sequences in a title can rewrite the screen or set the window title; pipes keep exact values for scripts.
- **D-INT10-8 The shell.** (a) Plain lines from stdin with the terminal's own line editing, prompts only on a terminal, no history, no idle close; (b) a line editor with history and arrow keys (a new crate, gate G6 and AT-J03). Recommend (a): no new crate, no typed commands kept in memory, and piped input works.
- **D-INT10-9 New vaults from the command line.** (a) Larsal's defaults (CRY-02.23, APP-07.19) with a benchmark for `-t` or 1,000 ms; (b) the reference's AES-KDF with a fixed 1,000,000 rounds when `-t` is missing. Recommend (a): the same vault as Larsal's wizard makes; the reference opens it (FMT-01 interop). `scripts/make-testdata.sh` uses the reference's own tool and is not affected.
- **D-INT10-10 Dates in db-info.** (a) RFC 3339 in local time; (b) the locale's short form, as the reference. Recommend (a): scripts can read it, and it shows the time zone.
- **D-INT10-11 Search scope.** (a) Group search flags ignored, as the reference; recycle bin never (LD-57); (b) exactly the reference, bin included; (c) flags honoured as in the window (FEA-01.20). Recommend (a): LD-57 says bin entries are never searched, and scripts expect to find entries in groups whose search is off. FEA-01 case T01's note ("lists E1, E5, E6") then reads "E1, E5" for Larsal.

### Not on Mac

- The reference's `-?` help option exists only on Windows.
- The reference copies through outside copy programs on Linux (Wayland or X11) and Windows; on macOS it uses the system's plain copy program. Larsal writes the pasteboard itself (APP-03.9).
- Windows console code page switching for UTF-8 output.
- Not shipped in the reference either: a fuzzing build that reads the password from an environment variable. Larsal never reads a password from the environment (INT-10.16).

## Parity table

"Same" means the same commands, options, arguments, stdout data and exit codes, with messages in Larsal's own words. "Larsal differs" names the difference and its reason. "Not on Mac" is reference behavior that exists only on other systems. Verify marks each row green when Larsal's black-box result matches this table (E12-S1).

| # | Reference | Larsal | Status | Reason or note |
|---|---|---|---|---|
| G1 | Option syntax: long, short, combined, `=`, `--`, any position | same | same | INT-10.2 |
| G2 | Usage error: message plus the full help on stderr, exit 1; an unknown top-level option alone: usage on stdout, exit 0 | one line M10-02, exit 1 | Larsal differs | Shorter output; a typo is an error (INT-10.3, INT-10.4) |
| G3 | `COMMAND --help`: stderr, exit 1, missing argument reported first | stdout, exit 0 | Larsal differs | Help that always works (INT-10.3) |
| G4 | Entry password prompts of add and edit, and the shell prompt, on stdout | every prompt on stderr | Larsal differs | stdout stays data only (INT-10.6) |
| G5 | Some option errors found after the unlock | all before the first prompt | Larsal differs | No password typed for nothing (INT-10.5) |
| G6 | `-q` hides unlock errors and clip's field error; mv and db-edit still print success lines; new-password prompts still print | errors always print; no prompt or success line with `-q` | Larsal differs | D-INT10-3, INT-10.7 |
| G7 | Quit signal at a password prompt leaves echo off | terminal restored, then the signal | Larsal differs | INT-10.12 step 5, LD-165 |
| G8 | Vault text printed exactly to a terminal | control characters escaped on a terminal | Larsal differs | D-INT10-7 |
| G9 | Key file equal to the vault: wrong credentials | refused with M06-30's text | Larsal differs | FMT-18.24 |
| G10 | Key derivation always runs | stops in the ask band unless `--allow-slow-unlock` | Larsal differs | CRY-02.14, D-INT10-6 |
| G11 | Exit codes 0 and 1 | same | same | D-INT10-2 |
| G12 | `-k`, `--key-file`; `--no-password`; `-q` | same | same | Except G6 and G14 |
| G13 | `-y`, `--yubikey` | `--hw-key` (alias kept) | same | Built with E10 (INT-07) |
| G14 | `--no-password` with no other key part: tries an empty key, wrong-credentials error | M10-14 before any work | Larsal differs | INT-10.12 |
| C1 | `add` | `add` | Larsal differs: an ENTRY that is empty or ends with `/` is refused with M10-26 (LD-172) | INT-10.21 |
| C2 | `analyze` | `analyze` | Larsal differs | No outside lookup program (D-06-10, SG-06); non-hex is a parse error (D-06-8); 64-bit counts (FEA-06.17); `--hash-file` named |
| C3 | `attachment-export` | `attachment-export` | Larsal differs | Mode 0600, no silent overwrite, `-f` (L05-5, SD-09) |
| C4 | `attachment-import` | `attachment-import` | same | INT-10.42 |
| C5 | `attachment-rm` | `attachment-rm` | same | INT-10.43 |
| C6 | `clip` | `clip` | Larsal differs | Markers and the still-ours check; cleared on a quit signal (SC-07, APP-03.20); countdown on stderr, terminal only; an empty field copies nothing (APP-03.5, LD-200 (8)) |
| C7 | `close` | `close` | same | INT-10.44 |
| C8 | `db-create` | `db-create` | Larsal differs | Larsal's KDF defaults and root name (D-INT10-9); key files always XML 2.0 (FMT-18.21) |
| C9 | `db-edit` | `db-edit` | Larsal differs | New key files always XML 2.0 (FMT-18.21) |
| C10 | `db-info` | `db-info` | Larsal differs | No per-open random id; RFC 3339 local times (D-INT10-10, FEA-07.20); passkey and one-time code rows |
| C11 | `diceware` | `passphrase` (alias kept) | Larsal differs | An empty or unreadable list is an error (D-03-4); at most 1,000 words (D-03-5) |
| C12 | `edit` | `edit` | same | INT-10.22 |
| C13 | `estimate` | `estimate` | Larsal differs | No password argument, no echo (D-INT10-4); length in characters; Larsal's estimator (FEA-05.1) |
| C14 | `export` | `export` | Larsal differs | Warning on stderr (LD-42); exact format names (D-INT10-5); attachment pool in every XML (FEA-09.14) |
| C15 | `generate` | `generate` | Larsal differs | Look-alike character of the extended set (D-02-1); length at most 10,000 (D-02-4) |
| C16 | `help` | `help` | same | INT-10.44 |
| C17 | `import` | `import` | Larsal differs | Protected values and DTDs refused instead of a crash (FEA-08.62); Larsal's KDF defaults (D-INT10-9) |
| C18 | `ls` | `ls` | same | INT-10.27 |
| C19 | `merge` | `merge` | Larsal differs | No values in change lines (D-11-10); Larsal's merge rules (MOD-11) |
| C20 | `mkdir` | `mkdir` | Larsal differs | Trailing `/` accepted (INT-10.23) |
| C21 | `mv` | `mv` | Larsal differs | No history item (L03-1) |
| C22 | `open` (shell) | `open` | Larsal differs | Piped input works; no line history (D-INT10-8) |
| C23 | `rm` | `rm` | same | INT-10.25 |
| C24 | `rmdir` | `rmdir` | Larsal differs | A group holding the bin is deleted, not a hang (MOD-04.4) |
| C25 | `search` | `search` | Larsal differs | Recycle bin never listed (LD-57, D-INT10-11) |
| C26 | `show` | `show` | same | INT-10.28 |
| C27 | `exit` (shell) | `exit` | same | INT-10.47 |
| C28 | `quit` (shell) | `quit` | same | INT-10.47 |
| T1 | no command: usage, exit 0 | same | same | F01 |
| T2 | `-h`, `--help` | same | same | F02 |
| T3 | `--help-all` (toolkit options) | alias of `--help` | Larsal differs | Larsal has no toolkit options |
| T4 | `-v`, `--version` | same | same | F03 |
| T5 | `--debug-info` | same | same | F04, APP-09.4 |
| T6 | none | `--license` | Larsal differs | F05: Larsal's own license-notice flag (E14-S2, LD-345); the reference has none |
| N1 | `-?` | none | not on Mac | Windows only in the reference |
| N2 | Copy through outside copy programs (Wayland, X11, Windows) | none | not on Mac | macOS uses the pasteboard (APP-03.9) |
| N3 | Console code page switching | none | not on Mac | Windows only |

Counts: 51 rows. Same 18 (G1, G11, G12, G13, C4, C5, C7, C12, C16, C18, C23, C26, C27, C28, T1, T2, T4, T5). Larsal differs 30 (G2 to G10, G14, 18 C rows including C1, T3, T6). Not on Mac 3.

## Security notes

- **SR-13:** prompts without echo (INT-10.12), stdin when not a terminal, protected values hidden unless named or `-s` (INT-10.28), no password in arguments or the environment (INT-10.16, D-INT10-4). Proof: cases INT-10.12-a to INT-10.12-d, INT-10.28-a to INT-10.28-d, INT-10.33-a.
- **SC-07:** the clipboard is marked and cleared only while still ours, also on a quit signal (INT-10.29). AT-D01, AT-D02. Cases INT-10.29-a to INT-10.29-d.
- **SG-06:** offline only, no outside program, no hash on any command line (INT-10.32).
- **SD-07:** every export warns (INT-10.36, LD-42).
- **SF-15, SR-05:** self-test and hardening before any secret is read (INT-10.1, APP-11).
- What must never happen: a secret in an error line, a note or a log; a secret printed by a command that was not asked for it; a generated password printed by add or edit; a terminal left without echo; a clipboard value left behind after a signal; a key derivation in the ask band without `--allow-slow-unlock`; vault text that drives the terminal (INT-10.10).
- The shell holds an unlocked vault until it ends (INT-10.47); its terminal is the user's to guard, as in the reference.
- A vault file and an XML document are hostile input: the format limits, AT-A01 to AT-A12 and FEA-08.67 apply to every command that opens one.
- Residual: data the user asks for (`show -s`, `-a Password`, `export`, `attachment-export --stdout`, `estimate -a`) leaves Larsal's secret types once written to stdout; the receiving program or file is outside Larsal's control.

## Test cases

Demo files: copy `testdata/*.larsalvault` and `testdata/*.larsalkey` into `/tmp/spec-int10/` and work there; use a fresh copy `w.larsalvault` of `rich-v3.larsalvault` (password `demo-pass-4`) for every changing case. `larsal` is the tool under test. Verify runs the reference tool on the same copies with a throwaway HOME under /tmp. Clip cases (INT-10.5-a, INT-10.29-a to INT-10.29-g) run a test build of `larsal` whose copy routine writes a private named pasteboard, never the general one (AGENTS.md rule 10); Verify does not run the reference's `clip`, which always writes the general pasteboard; its side comes from the source. "pty" means the command runs on a pseudo-terminal driven by a test script. Passwords: `password-only` `demo-pass-1`; `password-and-keyfile` `demo-pass-2` with `key-hex64.larsalkey`; `rich-v3` `demo-pass-4`; `rich-v4` `demo-pass-5`; `option-a-personal` `demo-pass-7`.

| Case | Given | When | Then |
|---|---|---|---|
| INT-10.1-a | Test build whose SHA-256 self-test vector is wrong | `larsal ls password-only.larsalvault` | M11-02 on stderr; exit 1; no prompt |
| INT-10.1-b | Same test build | `larsal --help` | M10-03; exit 0 |
| INT-10.2-a | — | `larsal generate -L12`; `larsal generate --length=12`; `larsal generate -L 12` | Each prints 12 characters; exit 0 |
| INT-10.2-b | — | `larsal generate -ln -L 40` | 40 characters, only lower-case letters and digits |
| INT-10.2-c | — | `printf 'demo-pass-1\n' \| larsal ls password-only.larsalvault -- -R` | M10-21 for `-R`; exit 1 |
| INT-10.2-d | — | `larsal generate --bogus` | M10-02 names `--bogus`; stdout empty; exit 1 |
| INT-10.3-a | — | `larsal`; `larsal --help`; `larsal --help-all` | stdout lists the 26 commands C01 to C26 (no `diceware`); exit 0 |
| INT-10.3-b | — | `larsal -v`; `larsal --version` | One line, the version number only; exit 0 |
| INT-10.3-c | — | `larsal --debug-info` | Version, build type, OS, CPU, kernel, features, crypto crates; no path, no setting; exit 0 |
| INT-10.3-d | — | `larsal show --help`; `larsal ls password-only.larsalvault --help` | Each command's help on stdout; exit 0; no prompt. Reference: stderr, exit 1, the first with the missing-argument error (observed) |
| INT-10.3-e | — | `larsal --license`; `larsal -v`; `larsal -h` | The F05 notice of INT-10.3: the copyright line, `Larsal Source-Available License 1.0`, the unmodified-use permission and written-permission restrictions, `NO WARRANTY`, `LICENSE` and `THIRD-PARTY-NOTICES.md` with where they ship, and `ATTRIBUTION` word for word as the last line; exit 0; then the version number alone (INT-10.3-b unchanged); then the usage line names `--license`. Test `e14_2_the_license_and_word_list_notices_are_shown` (crates/larsal-cli/tests/license.rs). The reference has no such flag (parity T6) |
| INT-10.4-a | — | `larsal diceware -W 3`; `larsal passphrase -W 3` | Three lower-case words each; exit 0 |
| INT-10.4-b | — | `larsal bogus`; `larsal --bogus` | M10-01; M10-02 without a command name; exit 1 each. Reference: the second prints its usage on stdout, exit 0 (observed) |
| INT-10.5-a | pty | `larsal clip password-only.larsalvault "Demo login" abc` | M10-61; no M10-10 prompt; exit 1 |
| INT-10.5-b | pty | `larsal add -g -p w.larsalvault X`; `larsal db-edit -p --unset-password w.larsalvault` | M10-31; M10-82; no prompt; exit 1 each |
| INT-10.6-a | — | `printf 'demo-pass-4\nentry-pw\n' \| larsal add -p w.larsalvault New1 >o 2>e` | `o` holds only M10-40; `e` holds M10-10 and M10-33. Reference: its entry prompt is in `o` (observed) |
| INT-10.7-a | — | `printf 'wrong\n' \| larsal ls -q password-only.larsalvault` | M06-06's text on stderr; exit 1. Reference: no output, exit 1 (observed) |
| INT-10.7-b | — | `printf 'demo-pass-4\n' \| larsal add -q w.larsalvault Q1` | No output on either stream; exit 0; entry `Q1` exists |
| INT-10.7-c | Hash file of INT-10.32-a | `printf 'demo-pass-1\n' \| larsal analyze -q -H h.txt password-only.larsalvault` | stdout holds only the finding line (no M10-86) |
| INT-10.8-a | — | `printf 'demo-pass-4\n' \| larsal search rich-v3.larsalvault zzzz`; `larsal ls` | Exit 1 (M10-72); exit 1 (M10-02), never 2 |
| INT-10.9-a | Larsal's settings folder hashed before | `larsal db-create -p n.larsalvault` (pw `pw-a` twice); `printf 'demo-pass-4\n' \| larsal add w.larsalvault S1` | Settings folder byte-identical after; no recent-list change; no history file anywhere under HOME |
| INT-10.10-a | Vault made by Larsal's test tool with an entry titled `Demo` ESC `[31mred` (password `demo-pass-1`) | `larsal ls` on a pty; `larsal ls \| od -c` | pty shows `Demo\x1b[31mred` as text and the colour does not change; the pipe holds the raw 0x1B byte |
| INT-10.11-a | — | `larsal ls none.larsalvault`; `larsal ls /tmp/spec-int10`; `chmod 000 c.larsalvault; larsal ls c.larsalvault` | M10-11; M10-12; M10-13; no prompt; exit 1 each |
| INT-10.12-a | pty | `larsal ls password-only.larsalvault`, type `demo-pass-1` | Prompt on stderr; the typed text is not echoed; a newline; `Demo login`; exit 0 |
| INT-10.12-b | pty | `larsal ls password-only.larsalvault`, send SIGINT at the prompt | Process ends by SIGINT; the terminal's echo is on afterwards. Reference: echo off (observed) |
| INT-10.12-c | — | `printf 'demo-pass-1\r\n' \| larsal ls password-only.larsalvault`; then with `'demo-pass-1 \n'` | Unlocks; second: M06-06's text, exit 1 |
| INT-10.12-d | `e.larsalvault` made by `printf '\ny\n' \| larsal db-create -p e.larsalvault` | `larsal ls e.larsalvault </dev/null`; `larsal ls --no-password e.larsalvault` | First unlocks (end of input = empty password); second M10-14, exit 1 |
| INT-10.12-e | — | `printf 'demo-pass-4\ndemo-pass-4\n' \| larsal merge m1.larsalvault m2.larsalvault -d` (copies of rich-v3, m2 with an extra entry) | Both lines read in order target, source; one `Added` line |
| INT-10.13-a | — | `larsal ls --no-password -k key-hex64.larsalkey keyfile-hex64.larsalvault`; same with `-q`; `-k key-xml-v2.larsalkey keyfile-xml-v2.larsalvault` | List and M10-16; list only; list only |
| INT-10.13-b | — | `printf 'demo-pass-1\n' \| larsal ls -k password-only.larsalvault password-only.larsalvault` | M06-30's text; exit 1. Reference: wrong credentials (observed) |
| INT-10.13-c | Empty file `empty.larsalkey` | `-k none.larsalkey`; `-k /tmp`; `-k empty.larsalkey` with password-only | M06-11; M06-14; M06-07 texts; exit 1 each |
| INT-10.13-d | — | `printf 'demo-pass-2\n' \| larsal ls -k key-hex64.larsalkey password-and-keyfile.larsalvault` | `Demo login` and M10-16; exit 0 |
| INT-10.14-a | Software challenge-response key (OD-01), slot 2, vault made with it (E10) | `larsal ls --hw-key 2 v.larsalvault`; `--hw-key 3`; `-y 2` | Unlocks, M10-18 while waiting; M10-02, exit 1; unlocks (alias) |
| INT-10.15-a | Argon2id header with m = 2 GiB, made by Larsal's test tool; test hooks fix physical memory at 16 GiB (CRY-02.14) and count KDF runs | `printf 'x\n' \| larsal ls big.larsalvault`; then with `--allow-slow-unlock` | M10-15 with "2.0 GiB", exit 1, 0 KDF runs; second: 1 KDF run, then M06-06 (wrong password) |
| INT-10.15-b | `notvault.larsalvault` = `hello`; `cut.larsalvault` = first 200 bytes of password-only | `printf 'x\n' \| larsal ls` each | M06-01's text; M06-04's text; exit 1 |
| INT-10.15-c | MOD-13 case T30 vault | `larsal ls` | One MOD-13.16 notice on stderr; list on stdout; exit 0; with `-q` no notice |
| INT-10.15-d | Copy of password-only with header version patched to 4.2 by Larsal's test tool (FMT-01) | `larsal ls` | M10-17 on stderr; the command runs |
| INT-10.16-a | — | `larsal estimate demo-pass-1`; code review of every option | M10-92, exit 1; no option or environment variable takes a secret |
| INT-10.16-b | — | `printf 'demo-pass-4\n' \| larsal add -g w.larsalvault G1 >o 2>e` | Neither `o` nor `e` holds the generated password (compare with `show -a Password`) |
| INT-10.17-a | — | `show rich-v3.larsalvault "Server login"`; `show ... Work/Servers/Server\ login`; `show ... "/Work/Servers/Server login"` | Same entry three times (UserName `admin`) |
| INT-10.17-b | — | `show rich-v3.larsalvault "Servers/Server login"` | M10-20; exit 1 |
| INT-10.17-d | `s.larsalvault` = copy of rich-v3 after `edit -t "Work/Servers/Server login" s.larsalvault "Full demo entry"` | `show -a Uuid s.larsalvault "Work/Servers/Server login"`; `show -a Uuid rich-v3.larsalvault /` | `{00000000-0000-0000-0000-00000000000a}` (the retitled root entry wins); `{00000000-0000-0000-0000-00000000000f}` (the untitled root entry). Same in the reference (observed) |
| INT-10.17-c | — | `add w.larsalvault "Server login"`; `add w.larsalvault "/Server login"` | M10-22, exit 1; second adds it to the root group |
| INT-10.18-a | — | `ls rich-v3.larsalvault Work/Servers`; `/Work/Servers/`; `Work/Servers/`; `ls rich-v3.larsalvault /`; `ls rich-v3.larsalvault ""` | First three equal (`Server login`, `Old servers/`); last two list the root |
| INT-10.19-a | — | `search rich-v3.larsalvault server` | `/Work/Servers/Server login` then `/Work/Servers/Old servers/Old server` |
| INT-10.20-a | `w.larsalvault` mode 0644 | `add w.larsalvault S2` | Mode still 0644; version per FMT-16; the reference opens it and lists `S2` |
| INT-10.20-b | Test hook rewrites `w.larsalvault` between unlock and save | `add w.larsalvault S3` | M10-91; exit 1; the file is the hook's version |
| INT-10.20-c | `w.larsalvault` in a folder made read-only | `add w.larsalvault S4` | M10-90 with the reason; exit 1; file unchanged |
| INT-10.21-a | — | `add w.larsalvault New1 -u u1 --url https://example.com/n --notes 'a\nb'` | `show -a UserName -a URL -a Notes` gives `u1`, the URL, `a` LF `b`; exit 0 |
| INT-10.21-b | rich-v3 has default user name `demo-user` (MOD-01.22) | `add w.larsalvault E2`; `show -a UserName` | Empty user name |
| INT-10.21-c | — | `add -g -L 12 -n w.larsalvault Gen1`; `add -g -L 0 w.larsalvault G0` | Password of 12 digits; M10-32 before the prompt, exit 1 |
| INT-10.21-d | — | `add w.larsalvault Nogroup/X` | M10-21 for `Nogroup`; exit 1 |
| INT-10.22-a | pty | `edit w.larsalvault "Full demo entry"` | M10-30 before any prompt; exit 1. Reference: after the unlock (observed) |
| INT-10.22-b | — | `edit -t Renamed -u "" w.larsalvault "Full demo entry"` | Title `Renamed`; user name still `demo-user`; one more history item; M10-41 names `Renamed` |
| INT-10.22-c | — | `edit -u demo-user w.larsalvault "Full demo entry"` | Exit 0; no new history item (MOD-03 case 03-02) |
| INT-10.23-a | — | `mkdir w.larsalvault Work/New` twice; `mkdir w.larsalvault Nope/New`; `mkdir w.larsalvault /Top/` | M10-42 then M10-23; M10-21; group `Top` made. Reference: `/Top/` fails (observed) |
| INT-10.24-a | Gen1 in root with 0 history items | `mv w.larsalvault Gen1 Work` twice; `mv w.larsalvault Gen1 Nope` | Moved, 0 history items; M10-24; M10-21 |
| INT-10.25-a | Gen1 in root (made as in INT-10.21-c) | `rm w.larsalvault Gen1`; `rm w.larsalvault "Recycle Bin/Gen1"`; `rm w.larsalvault Gen1` | Recycled; deleted for good with a deleted-object record; M10-20 |
| INT-10.25-b | password-only copy with the bin turned off by Larsal's test tool | `rm p.larsalvault "Demo login"` | Deleted for good (M10-44 second form) |
| INT-10.26-a | — | `rmdir w.larsalvault Personal`; `rmdir w.larsalvault /`; `rmdir w.larsalvault ""` | Group in the bin; M10-25; M10-25 |
| INT-10.26-b | Copy of rich-v3 where Larsal's test tool moved the bin into `Personal` | `rmdir w.larsalvault Personal` | Done within 2 s; `Personal`, the bin and its content deleted for good (MOD-04 case 04-09) |
| INT-10.27-a | — | `ls rich-v3.larsalvault`; `ls -R`; `ls -R -f` | Six lines: five titles and one empty line (the untitled entry), then `Work/`, `Personal/`, `Recycle Bin/`; `-R` indents by two spaces and shows `(empty group)` under Personal; `-R -f` shows `Work/Servers/Old servers/Old server` and `Personal/(empty group)` |
| INT-10.28-a | — | `show rich-v3.larsalvault "Full demo entry"` | Seven lines; `Password: (hidden)`; `Uuid: {00000000-0000-0000-0000-00000000000a}`; `Tags: demo,work`; Notes over four lines |
| INT-10.28-b | — | Same with `--all` | Then `Demo PIN: (hidden)`, `Demo hint: not protected`, `Empty custom field: `, `Spaces:   leading and trailing  `, `otp: (hidden)` |
| INT-10.28-c | — | Same with `-s` | `Password: demo-entry-pass-2` |
| INT-10.28-d | — | `-a Password -a username -a "demo pin" -a uuid` | `demo-entry-pass-2`, `demo-user`, `0000`, then M10-63 for `uuid`; exit 1 |
| INT-10.28-e | — | `show -t rich-v3.larsalvault "Full demo entry"`; `show -t ... "Server login"` | Six digits equal to FEA-04's code for secret `JBSWY3DPEHPK3PXP` at that time; M10-65, exit 1 |
| INT-10.28-f | — | `show --show-attachments rich-v3.larsalvault "Full demo entry"` | Fields, empty line, `Attached files:`, `  bytes.bin (256 B)`, `  empty.bin (0 B)`, `  notes.txt (20 B)` |
| INT-10.28-g | Entry with fields `pin` and `PIN` (Larsal's test tool) | `show -a Pin` | M10-64 listing both; exit 1 |
| INT-10.29-a | Pasteboard test as APP-03 T40 | `printf 'demo-pass-4\n' \| larsal clip w.larsalvault "Full demo entry" 2` | Pasteboard holds `demo-entry-pass-2` with the concealed and transient types; empty at t = 2 (± 0.5); M10-70 first form; exit 0 |
| INT-10.29-b | Same | Timeout 2; another app writes `other` at t = 1 | At t = 3 the pasteboard holds `other`; M10-70 second form |
| INT-10.29-c | Same | Timeout 0 | Exits at once; value stays on the pasteboard |
| INT-10.29-d | Same | Timeout 30; SIGINT at t = 1 | Pasteboard empty; process ends by SIGINT. Reference (source): value stays |
| INT-10.29-e | — | `clip -t w.larsalvault "Full demo entry"`; `clip -a Title -t ...` | The current code copied; M10-62 before the prompt |
| INT-10.29-f | — | `clip -b w.larsalvault "Old serv" 0`; `clip -b w.larsalvault e` | M10-67 `/Work/Servers/Old servers/Old server`; M10-66 list on stderr, exit 1, pasteboard unchanged |
| INT-10.29-g | — | `clip -a nothere w.larsalvault "Full demo entry"` | M10-63 on stderr; exit 1. Reference: on stdout (observed) |
| INT-10.29-h | Pasteboard test as INT-10.29-a; the pasteboard holds `before` | `printf 'demo-pass-4\n' \| larsal clip -a "Empty custom field" w.larsalvault "Full demo entry" 2`; the same for `"Shared attachment 1"` (empty password, default field) | Each time: M10-98 on stderr; exit 1; the pasteboard still holds `before` and its change count is unchanged; no wait. Reference: copies an empty string |
| INT-10.30-a | — | `search rich-v3.larsalvault deleted`; `search rich-v3.larsalvault server` | M10-72, exit 1 (reference lists the two bin entries, observed); the two Work entries although Work has search off |
| INT-10.30-b | — | `printf 'demo-pass-7\n' \| larsal search option-a-personal.larsalvault is:expired` | The same paths as the reference prints (MOD-09) |
| INT-10.31-a | — | `printf 'demo-pass-5\n' \| larsal db-info rich-v4.larsalvault` | No id line; Recycle bin `on`; Groups 5, Entries 8, Past expiry 1, Different passwords 5, Repeated 0, Most uses 1, Under 8 characters 0, Rated below Good 4, Skipped in reports 1, Length on average `15 characters`; times RFC 3339 with offset |
| INT-10.32-a | `h.txt` = upper-case SHA-1 of `demo-entry-pass-1`, `:3`, CR LF | `printf 'demo-pass-1\n' \| larsal analyze -H h.txt password-only.larsalvault` | M10-86, then `Leaked password: Demo login (in the list 3 times)`; exit 0 |
| INT-10.32-b | — | `larsal analyze password-only.larsalvault`; `larsal analyze --okon x -H h.txt password-only.larsalvault`; `--hibp h.txt` | M10-85 before the prompt; M10-02 for `--okon`; works (alias) |
| INT-10.33-a | — | `printf 'demo-pass-1\n' \| larsal estimate`; pty `larsal estimate`, type `demo-secret-9` | `Characters 11`, bits per FEA-05; pty: M10-93, nothing echoed. Reference: echoes (observed) |
| INT-10.33-b | — | `printf '\xc3\xa9\n' \| larsal estimate`; `printf '\n' \| larsal estimate` | `Characters 1` (reference: length 2, observed); `Characters 0`, `Bits 0.000`, `Log10 0.000` |
| INT-10.34-a | — | `larsal generate` 300 times; `larsal generate -L 10001` | FEA-02 case "command line defaults": 32 characters from the 53-character pool; M10-32, exit 1 |
| INT-10.35-a | — | `larsal passphrase -W 0`; `-W 1001`; `larsal passphrase -w /tmp/spec-int10/none.txt` | M10-35, exit 1 (twice); error (D-03-4), exit 1 |
| INT-10.36-a | — | `printf 'demo-pass-1\n' \| larsal export -q password-only.larsalvault`; `-f csv`; `-f HTML`; `-f xmlx` | XML on stdout and M10-88 on stderr even with `-q`; CSV; HTML; MSG-EXP-FORMAT, exit 1 (reference: XML) |
| INT-10.37-a | `x.xml` = Larsal's XML export of password-only | `printf 'pw\npw\n' \| larsal import -p x.xml i1.larsalvault`; again; `larsal import x.xml i2.larsalvault` | Made, mode 0600, `Demo login` inside; MSG-XML-EXISTS before any prompt; MSG-XML-NOKEY, nothing made |
| INT-10.38-a | — | `larsal db-create n1.larsalvault`; `printf 'pw-a\npw-a\n' \| larsal db-create -p n2.larsalvault` | M10-76, nothing made; n2 made, mode 0600, root `Root`, Argon2id 64 MiB, empty name; the reference opens n2 with `pw-a` |
| INT-10.38-b | — | `-p` with `pw-a`,`pw-b`; with empty then `n`; with empty then `y` | M10-79, nothing; M10-79 second form, nothing; made, unlocks with an empty line |
| INT-10.38-c | — | `-t 99`; `-t abc`; `-p -t 100` | M10-77 before the prompt (twice); M10-49, unlock takes about 100 ms |
| INT-10.38-d | `nk.larsalkey` missing; `old.larsalkey` = copy of `key-hashed.larsalkey` | `db-create --set-key-file nk.larsalkey n3.larsalvault`; `db-create --set-key-file old.larsalkey n4.larsalvault` | nk.larsalkey made: XML 2.0, 278 bytes, mode 0400; old.larsalkey unchanged and n4 opens with it |
| INT-10.38-e | n2 exists | `larsal db-create -p n2.larsalvault` | M10-75 before any prompt; exit 1 |
| INT-10.39-a | n2 (password `pw-a`) | `db-edit n2`; `db-edit --unset-key-file n2`; `db-edit --unset-password n2`; `db-edit --set-key-file nk2.larsalkey n2` | M10-51 "nothing changed", exit 0; M10-83; M10-84; saved, and n2 then needs `pw-a` and nk2.larsalkey |
| INT-10.40-a | m1, m2 copies of rich-v3, m2 with entry `Merged in` | `merge -q -d m1 m2`; `merge -d m1 m2`; `merge -s m1 m2` twice | No output on stdout; then one line TAB `Added: '/Rich demo'/'Merged in' [{…}]` and M10-52 unchanged (m1 bytes unchanged); saved; then M10-52 unchanged |
| INT-10.40-b | — | `printf 'demo-pass-4\n' \| larsal merge -s m1.larsalvault password-only.larsalvault` | M10-97 with M06-06's text; exit 1 |
| INT-10.41-a | umask 022 | `attachment-export w "Full demo entry" notes.txt`; `--stdout`; to `out.bin`; to `out.bin` again with stdin from a pipe; again with `-f` | M10-58; bytes `demo attachment one`; out.bin mode 0600; M10-59 refusal, file unchanged; replaced |
| INT-10.42-a | `in.txt` with any text | `attachment-import w "Full demo entry" notes.txt in.txt`; with `-f`; `attachment-import w "Full demo entry" notes.txt none.txt` | M10-56; replaced, one history item; M10-56 (the name is checked before the file, as the reference, observed) |
| INT-10.43-a | — | `attachment-rm w "Full demo entry" new.txt`; `... notes.txt` | M10-55; removed |
| INT-10.44-a | — | `larsal help ls`; `larsal help nothing`; `larsal close` | ls help, exit 0; M10-03, exit 0; no output, exit 0 |
| INT-10.45-a | pty | `larsal open rich-v3.larsalvault`, then `demo-pass-4`, `ls`, `show "Full demo entry"`, `bogus`, `export`, `close`, `ls`, `quit` | Prompt `larsal (Rich demo)> `; the listing; the fields; M10-95 twice; after close the prompt `larsal> `; `ls` gives M10-02 (VAULT missing); exit 0 |
| INT-10.45-b | — | `printf 'demo-pass-4\nls\nquit\n' \| larsal open rich-v3.larsalvault` | The root listing on stdout; no shell prompt. Reference: nothing after its first prompt (observed) |
| INT-10.45-c | pty, shell on w.larsalvault | `add S5`, then (before quit) the reference lists w | `S5` is already in the file |
| INT-10.46-a | Shell on rich-v3 | `show "Full demo entry"`; `show Full\ demo\ entry`; `show Full demo entry` | Same entry twice; third: M10-02 (unexpected argument) |
| INT-10.47-a | pty, shell open | SIGTERM; in another run Ctrl-D | Ends by SIGTERM, terminal restored; exit 0 |

## How this was learned

- Read in the reference source (development branch): the tool's entry point (command table, top-level options, the interactive loop), the shared command base (common options, parser setup, the missing and extra argument checks, help text), the vault command base (unlock first, the shell's open vault), the helper module (password reading with echo off, the confirmed-password flow, the unlock routine and its file checks, key file loading and creation, the clipboard routine, the shell's line splitting, attribute lookup), the line reader, and every command's routine: options, checks, outputs, saves and exit codes. Also the group path lookups, the group listing routine, the entry path routine, the entry searcher's "ignore group flags" switch, the size formatter, the date formatter, the KDF and cipher names, and the statistics used by the info command.
- Compared the source's tool folder with the installed 2.7.11 tag through the reference's change history (read only): the same behavior except code clean-up, the passkey and one-time code rows of the info command, and the line reader moved into its own file.
- Ran the installed reference tool 2.7.11 with a throwaway HOME under `/tmp/spec-int10/` on copies of the project's demo vaults and key files: top-level help, version and debug info; usage errors and their codes; prompts and their streams; wrong password, missing, folder and unreadable vaults, bad and early key files, the vault as its own key file; quiet mode (unlock errors hidden, analyze line kept); `ls` with `-R` and `-f`; `show` with every option; clip's error paths (not the copy itself, to leave the Mac's clipboard alone); `search` (bin entries listed); `db-info` (a fresh id per run); `add`, `edit`, `mkdir` (trailing slash), `mv`, `rm`, `rmdir`; the three attachment commands; `db-create` and `db-edit` flows; `export`, `import`, `merge`, `generate`, `diceware`, `estimate` (byte length), `analyze`.
- Drove the reference tool on a pseudo-terminal with a small python3 script: no echo at the unlock and entry prompts, echo at the estimate prompt, echo left off after SIGINT at a prompt, the interactive mode (prompt, unknown commands, close, open, help, quit, export and import refused), and piped input to the interactive mode (lost after the password).
- F05 (`--license`, 2026-10-31, E14-S2) is Larsal's own flag: read from Larsal's code (crates/larsal-cli/src/main.rs `license_notice`, args.rs usage line), its test (crates/larsal-cli/tests/license.rs) and security/parity/E14-S2-license.md. The reference was not opened for it.

## Review 2026-10-28

Second Spec review. Read the reference source again (the entry point and interactive loop, the command bases, the helper module, the line reader, every command's routine, the group path, listing and entry path routines, the searcher, the size formatter) and ran the installed reference tool 2.7.11 with a throwaway HOME under /tmp on copies of `testdata/` vaults. `clip` was not run (AGENTS.md rule 10); its side is from the source. Every reference command (28) and option is in the card. Every Larsal message was compared with the reference's English strings; near matches were rewritten.

Fixes made in this review (19): the LD-171 line under Lead decisions; help lines C05 and C21 and messages M10-62 and M10-86 rewritten (too close to the reference's words); M10-69 moved to stderr, as INT-10.6 requires (INT-10.29, streams list, C6); INT-10.4 and G2: an unknown top-level option exits 1 (the reference shows its usage and exits 0); INT-10.5: M10-30 is found before the prompt; INT-10.6 and G4: the reference's shell prompt is on stdout; INT-10.7 and G6: the reference's other `-q` gaps (mv and db-edit success lines, new-password prompts, clip's field error), and merge `-q` drops the change lines (INT-10.40); INT-10.17: a `/` in a name makes a path ambiguous, it does not make it unreachable, and an untitled entry is found by `G/` (edge case corrected, case INT-10.17-d); INT-10.21: `-p` also restores the terminal on a signal; INT-10.28: `--all` lists the other fields sorted by name, not in stored order; INT-10.34 and INT-10.35: the built limits D-02-4 (length 10,000) and D-03-5 (1,000 words), with C11, C15 and cases; INT-10.41: `-q` refuses to overwrite; INT-10.42: the name is checked before the file is read (case fixed: `in.txt` must exist); cases INT-10.25-a (Gen1 given) and INT-10.27-a (six lines); clip cases run on a private named pasteboard and Verify does not run the reference's `clip`; the analyze row names the refused `--okon`.

Findings for the lead (4), each with a proposed ruling:

- **R10-1 add with no title.** `add v Personal/` makes an entry with an empty title in the reference (observed: its success line named an empty title); so does `add v /` when the root group has no untitled entry (source). The card says nothing. Proposed: refuse an ENTRY that is empty or ends with `/`, before any prompt, with a new message M10-26 "larsal: <path> gives no title for the new entry."; C1 then reads "Larsal differs". Reason: it is almost always a typo, and the untitled entry is then found only by `G/`.
- **R10-2 Secrets through placeholders in show.** `show` without `-s` resolves every printed value (MOD-08.25). A non-protected field that holds `{PASSWORD}`, `{S:<protected field>}` or `{REF:P@I:...}` therefore prints a protected value in clear, while the Password line says `(hidden)` (the reference does the same, from the source). Proposed: without `-s`, show resolves with the protected-value mask of D-08-4 (MOD-08.23) and prints a masked part as `(hidden)`; `-s` and `-a NAME` print the full resolution. MOD-08.25's command line row changes to match. Reason: SR-13 says protected values are hidden unless asked.
- **R10-3 One-time password and passkey fields.** LD-165 (F-057) makes the window's Show refuse the one-time password and passkey fields by name; `show -a`, `show --all -s` and `clip -a` print them (INT-10.28, INT-10.29, INT-04.55), as the reference. Proposed: keep the command line as written (naming a field, or `-s`, is the ask) and add to INT-10.28 that F-057's refusal is a window rule only. Reason: scripts that read a one-time password URI or a passkey field keep working; the user typed the request.
- **R10-4 INT-04.55 wording.** INT-04.55 says the command line prints protected passkey fields as `PROTECTED`; Larsal prints `(hidden)` (INT-10.28). Proposed: INT-04's owner changes the word to `(hidden)`.

