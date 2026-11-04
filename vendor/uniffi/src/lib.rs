/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/// Reexport items from other uniffi creates
pub use uniffi_core::*;
pub use uniffi_macros::*;
// App change (E0-S7 step 5): the `cli` module and the `bindgen-tests`
// re-exports are cut with their features (Cargo.toml changes 3 and 4).

#[cfg(all(feature = "cargo-metadata", feature = "bindgen"))]
pub use uniffi_bindgen::cargo_metadata::CrateConfigSupplier as CargoMetadataConfigSupplier;
#[cfg(feature = "bindgen")]
pub use uniffi_bindgen::{
    bindings::{
        generate, generate_swift_bindings, GenerateOptions, SwiftBindingsOptions, TargetLanguage,
    },
    generate_bindings,
    library_mode::generate_bindings as generate_bindings_library_mode,
    print_repr,
};
#[cfg(feature = "build")]
pub use uniffi_build::{generate_scaffolding, generate_scaffolding_for_crate};

#[cfg(test)]
mod test {
    #[test]
    fn trybuild_ui_tests() {
        let t = trybuild::TestCases::new();
        t.compile_fail("tests/ui/*.rs");
    }
}
