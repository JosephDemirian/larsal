//! Plain exports from the window (FEA-09, INT-04.50, SD-07): the whole
//! vault as CSV, HTML or XML, and one entry's passkey file.
//!
//! Guarantees:
//! - every plain export warns (SD-07): each call writes nothing unless the
//!   screen says it showed the warning (`warned`), and the refusal carries
//!   the warning's text; the texts come from app-core ([`export_warning`],
//!   [`passkey_export_warning`]);
//! - the export is built in Rust in a wiping buffer from the vault in
//!   memory (unsaved changes included, nothing changed) and written
//!   straight to the file with app-core's `write_export`: 0600, atomic,
//!   never through a link (FEA-09.15, FEA-09.18, SD-09). Swift sends only
//!   the path and the options; no exported value crosses;
//! - error texts name the format, the file and the system's reason only.

use crate::session::{AppError, Session};
use crate::views::{now, parse_id};
use app_core::export::{self, Format, html, passkey};
use app_core::{recycle, storage};
use std::path::Path;

/// The three formats of File > Export (FEA-09.17).
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum ExportFormat {
    /// ACT-EXPORT-CSV.
    Csv,
    /// ACT-EXPORT-HTML.
    Html,
    /// ACT-EXPORT-XML.
    Xml,
}

impl ExportFormat {
    fn core(self) -> Format {
        match self {
            ExportFormat::Csv => Format::Csv,
            ExportFormat::Html => Format::Html,
            ExportFormat::Xml => Format::Xml,
        }
    }
}

/// The HTML dialog's "sort entries by" (FEA-09.7), in dialog order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, uniffi::Enum)]
pub enum ExportSort {
    /// Name, ascending: the default.
    #[default]
    NameAscending,
    /// Name, descending.
    NameDescending,
    /// The order in the vault.
    VaultOrder,
}

/// `MSG-EXP-CONFIRM` for one format (FEA-09.2): CSV and XML ask it (Yes,
/// No; No the default) before the save panel; HTML shows it as the
/// dialog's banner.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct ExportWarning {
    /// The question's title.
    pub title: String,
    /// The text; CSV adds the formula line (LD-43).
    pub text: String,
    /// True: ask before the save panel; false (HTML): the banner.
    pub asks_first: bool,
    /// The save panel's extension.
    pub extension: String,
}

/// What one passkey export did (INT-04.50 step 4).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum PasskeyExport {
    /// The file was written (0600).
    Written {
        /// Its path.
        path: String,
    },
    /// A file of that name is there and `replace` was off: ask MI04-32,
    /// then call again with `replace` for Yes.
    Exists {
        /// The file name.
        file: String,
    },
}

/// The warning of `format` (FEA-09.2, SD-07).
#[uniffi::export]
#[must_use]
pub fn export_warning(format: ExportFormat) -> ExportWarning {
    let f = format.core();
    ExportWarning {
        title: export::CONFIRM_TITLE.to_owned(),
        text: export::warning(f),
        asks_first: f.asks_first(),
        extension: f.extension().to_owned(),
    }
}

/// MI04-30 (INT-04.50 step 1, SD-07): asked before every passkey export.
#[uniffi::export]
#[must_use]
pub fn passkey_export_warning() -> String {
    passkey::WARNING.to_owned()
}

#[uniffi::export]
impl Session {
    /// File > Export (FEA-09.15): writes vault `vault` as `format` to
    /// `path` (the save panel asked before replacing a file). `sort` is the
    /// HTML dialog's choice (ignored for CSV and XML). Nothing is written
    /// unless `warned`: the screen showed [`export_warning`] and the user
    /// said Yes (CSV, XML) or OK under the banner (HTML).
    ///
    /// # Errors
    /// `UnknownVault`, `Locked`, `TooLong` for a path over 4,096 bytes;
    /// `Refused` with the warning when not `warned`, or with
    /// `MSG-EXP-FAILED` (any file at `path` is unchanged).
    pub fn export_vault(
        &self,
        vault: u64,
        format: ExportFormat,
        path: String,
        sort: ExportSort,
        warned: bool,
    ) -> Result<(), AppError> {
        let f = format.core();
        if !warned {
            return Err(AppError::Refused(export::warning(f)));
        }
        if path.len() > 4096 {
            return Err(AppError::TooLong);
        }
        let data = self.with_open(vault, |v, file, _| match f {
            Format::Csv => Ok(export::csv::csv(v, now())),
            Format::Html => {
                let file = file.display().to_string();
                let sort = match sort {
                    ExportSort::NameAscending => html::Sort::NameAscending,
                    ExportSort::NameDescending => html::Sort::NameDescending,
                    ExportSort::VaultOrder => html::Sort::VaultOrder,
                };
                // ponytail: no icons yet (FEA-09.12); add the decoded
                // custom and standard icon PNGs when the screen has them.
                Ok(html::html(
                    v,
                    &html::Options {
                        sort,
                        path: &file,
                        icon: None,
                    },
                ))
            }
            Format::Xml => export::xml::xml(v).map_err(|e| crate::edit::refused(&e)),
        })?;
        storage::write_export(Path::new(&path), data.expose()).map_err(|e| {
            AppError::Refused(format!(
                "App couldn't save the {} export: {e}. Any file already at that place is unchanged.",
                f.name()
            ))
        })
    }

    /// The Passkeys report's Export Selected (INT-04.50 step 4) for entry
    /// `entry`: writes its `.passkey` file (INT-04.49) into `folder` under
    /// the clean title, 0600, replacing a file there in one step only with
    /// `replace`. Nothing is written unless `warned`: the screen asked
    /// [`passkey_export_warning`] and the user said Yes.
    ///
    /// # Errors
    /// `UnknownVault`, `Locked`, `UnknownEntry` (also outside the report:
    /// in the recycle bin or without a private key), `TooLong`; `Refused`
    /// with MI04-30 when not `warned`, or MI04-33 when the write fails.
    pub fn export_passkey(
        &self,
        vault: u64,
        entry: String,
        folder: String,
        warned: bool,
        replace: bool,
    ) -> Result<PasskeyExport, AppError> {
        if !warned {
            return Err(AppError::Refused(passkey::WARNING.to_owned()));
        }
        if folder.len() > 4096 {
            return Err(AppError::TooLong);
        }
        let id = parse_id(&entry, AppError::UnknownEntry)?;
        let (data, file) = self.with_open(vault, |v, _, _| {
            let e = crate::views::find(&v.root, id, &mut Vec::new())
                .filter(|_| !recycle::entry_in_bin(v, id))
                .ok_or(AppError::UnknownEntry)?;
            let data = passkey::file(e).ok_or(AppError::UnknownEntry)?;
            Ok((data, passkey::file_name(e)))
        })?;
        let path = Path::new(&folder).join(&file);
        if !replace && std::fs::symlink_metadata(&path).is_ok() {
            return Ok(PasskeyExport::Exists { file });
        }
        storage::write_export(&path, data.expose()).map_err(|_| {
            AppError::Refused(format!(
                "Could not save {}. Moving on to the next passkey.",
                path.display()
            ))
        })?;
        Ok(PasskeyExport::Written {
            path: path.to_string_lossy().into_owned(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::views::ListView;
    use app_crypto::secret::SecretString;
    use app_model::entry::Field;
    use std::os::unix::fs::PermissionsExt;

    /// SD-07 (FEA-09.2, INT-04.50): no plain export is written without the
    /// warning; with it, each format and the passkey file land at 0600.
    #[test]
    fn sd_07_every_plain_export_warns() {
        let dir = std::env::temp_dir().join(format!("app-ffi-export-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let vault = dir.join("Personal.appvault");
        std::fs::copy(
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../testdata/option-a-personal.appvault"
            ),
            &vault,
        )
        .unwrap();
        let s = Session::new();
        let v = s.open(vault.to_string_lossy().into_owned()).unwrap();
        s.unlock(v, Some("demo-pass-7".into()), None).unwrap();
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        for (format, start) in [
            (ExportFormat::Csv, &b"\"Group\""[..]),
            (ExportFormat::Html, b"<!DOCTYPE html>"),
            (ExportFormat::Xml, b"<?xml"),
        ] {
            let w = export_warning(format);
            assert!(w.text.contains("plain text"), "{w:?}");
            assert_eq!(w.asks_first, format != ExportFormat::Html);
            let out = dir.join(format!("out.{}", w.extension));
            let path = out.to_string_lossy().into_owned();
            assert_eq!(
                s.export_vault(v, format, path.clone(), ExportSort::default(), false),
                Err(AppError::Refused(w.text.clone()))
            );
            assert!(!out.exists(), "nothing written without the warning");
            s.export_vault(v, format, path, ExportSort::default(), true)
                .unwrap();
            assert!(
                std::fs::read(&out).unwrap().starts_with(start),
                "{format:?}"
            );
            assert_eq!(mode(&out), 0o600);
        }
        // The passkey export (INT-04.50): MI04-30 first.
        let row = s.list(v, ListView::All).unwrap().rows.remove(0);
        s.with_edit(v, |vault, _, _, _| {
            let id = parse_id(&row.id, AppError::UnknownEntry)?;
            app_core::edit::change_entry(vault, id, now(), |e| {
                for (name, value) in [
                    ("KPEX_PASSKEY_RELYING_PARTY", "shop.example"),
                    (
                        "KPEX_PASSKEY_PRIVATE_KEY_PEM",
                        "-----BEGIN PRIVATE KEY-----",
                    ),
                ] {
                    e.set_field(
                        name.into(),
                        Field {
                            value: SecretString::new(value.into()),
                            protected: true,
                        },
                    );
                }
            })
            .map_err(|e| crate::edit::refused(&e))
        })
        .unwrap();
        let folder = dir.join("passkeys").to_string_lossy().into_owned();
        std::fs::create_dir_all(&folder).unwrap();
        assert_eq!(
            s.export_passkey(v, row.id.clone(), folder.clone(), false, false),
            Err(AppError::Refused(passkey_export_warning()))
        );
        assert_eq!(std::fs::read_dir(&folder).unwrap().count(), 0);
        let PasskeyExport::Written { path } = s
            .export_passkey(v, row.id.clone(), folder.clone(), true, false)
            .unwrap()
        else {
            panic!("written")
        };
        assert_eq!(mode(Path::new(&path)), 0o600);
        assert!(
            std::fs::read_to_string(&path)
                .unwrap()
                .contains("shop.example")
        );
        assert!(matches!(
            s.export_passkey(v, row.id, folder, true, false).unwrap(),
            PasskeyExport::Exists { .. }
        ));
        let _ = std::fs::remove_dir_all(dir);
    }
}
