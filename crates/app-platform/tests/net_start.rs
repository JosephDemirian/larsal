//! SN-01 (E6-S7): the network client does nothing until a caller asks. Its
//! own test binary, so no other test opens files or sockets meanwhile.
#![cfg(feature = "net")]

use app_platform::net::{Client, Timeouts};

fn open_files() -> usize {
    std::fs::read_dir("/dev/fd").unwrap().count()
}

#[test]
fn sn01_nothing_runs_until_asked() {
    // No global client, no thread, no start-up hook in the module: the only
    // way to a connection is a caller making a `Client` and calling it.
    let src = include_str!("../src/net.rs");
    for word in [
        "\nstatic ",
        " static ",
        "OnceLock",
        "LazyLock",
        "thread::spawn",
        "#[ctor",
        "lazy_static",
    ] {
        assert!(!src.contains(word), "{word}");
    }
    // Making a client opens no socket (nor any other file).
    let before = open_files();
    let client = Client::new(Timeouts::default()).unwrap();
    assert_eq!(open_files(), before);
    drop(client);
}
