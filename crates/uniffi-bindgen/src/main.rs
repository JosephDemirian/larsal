//! `uniffi-bindgen-swift`: writes the Swift bindings, the C header and the
//! module map for larsal-ffi (scripts/build-core.sh). Larsal's own command line
//! (E0-S7 step 5): only the options build-core.sh passes, so UniFFI's `cli`
//! feature, and clap with it, is not needed.
#![forbid(unsafe_code)]

use std::process::ExitCode;
use uniffi::{SwiftBindingsOptions, generate_swift_bindings};

const USAGE: &str = "usage: uniffi-bindgen-swift [--swift-sources] [--headers] [--modulemap] \
                     [--module-name NAME] [--modulemap-filename NAME] LIBRARY OUT_DIR";

fn main() -> ExitCode {
    let options = match parse(std::env::args().skip(1)) {
        Ok(options) => options,
        Err(problem) => {
            eprintln!("uniffi-bindgen-swift: {problem}\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    match generate_swift_bindings(options) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{e:?}");
            ExitCode::FAILURE
        }
    }
}

/// The options, then the library and the output folder; at least one of
/// the three kinds of output.
fn parse(args: impl IntoIterator<Item = String>) -> Result<SwiftBindingsOptions, String> {
    let mut options = SwiftBindingsOptions::default();
    let mut args = args.into_iter();
    let mut paths = Vec::new();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--swift-sources" => options.generate_swift_sources = true,
            "--headers" => options.generate_headers = true,
            "--modulemap" => options.generate_modulemap = true,
            "--module-name" => options.module_name = Some(value(&mut args, &arg)?),
            "--modulemap-filename" => options.modulemap_filename = Some(value(&mut args, &arg)?),
            _ if arg.starts_with('-') => return Err(format!("unknown option {arg}")),
            _ => paths.push(arg),
        }
    }
    let Ok([source, out_dir]) = <[String; 2]>::try_from(paths) else {
        return Err("give the library and the output folder".to_owned());
    };
    if !(options.generate_swift_sources || options.generate_headers || options.generate_modulemap) {
        return Err("give --swift-sources, --headers or --modulemap".to_owned());
    }
    options.source = source.into();
    options.out_dir = out_dir.into();
    Ok(options)
}

fn value(args: &mut impl Iterator<Item = String>, name: &str) -> Result<String, String> {
    args.next().ok_or_else(|| format!("{name} needs a value"))
}

#[cfg(test)]
mod tests {
    use super::parse;

    fn args(line: &str) -> Vec<String> {
        line.split(' ').map(str::to_owned).collect()
    }

    #[test]
    fn the_two_build_core_command_lines() {
        let o = parse(args("--swift-sources lib.a out/Swift")).unwrap();
        assert!(o.generate_swift_sources && !o.generate_headers && !o.generate_modulemap);
        assert_eq!(
            (o.source.as_str(), o.out_dir.as_str()),
            ("lib.a", "out/Swift")
        );
        assert_eq!((o.module_name, o.modulemap_filename), (None, None));

        let o = parse(args(
            "--headers --modulemap --module-name LarsalFFI --modulemap-filename module.modulemap lib.a out/include",
        ))
        .unwrap();
        assert!(!o.generate_swift_sources && o.generate_headers && o.generate_modulemap);
        assert_eq!(
            (o.source.as_str(), o.out_dir.as_str()),
            ("lib.a", "out/include")
        );
        assert_eq!(o.module_name.as_deref(), Some("LarsalFFI"));
        assert_eq!(o.modulemap_filename.as_deref(), Some("module.modulemap"));
        // The options the old command line had and build-core.sh never passes stay off.
        assert!(!o.xcframework && !o.metadata_no_deps && o.link_frameworks.is_empty());
        assert!(o.config.is_none());
    }

    #[test]
    fn problems() {
        for (line, problem) in [
            (
                "lib.a out",
                "give --swift-sources, --headers or --modulemap",
            ),
            ("--headers lib.a", "give the library and the output folder"),
            (
                "--headers lib.a out extra",
                "give the library and the output folder",
            ),
            (
                "--headers --xcframework lib.a out",
                "unknown option --xcframework",
            ),
            (
                "--headers lib.a out --module-name",
                "--module-name needs a value",
            ),
        ] {
            assert_eq!(parse(args(line)).unwrap_err(), problem, "{line}");
        }
    }
}
