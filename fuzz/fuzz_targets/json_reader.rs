//! Fuzz target `json_reader` (E0-S7 R12): App's own JSON reader
//! (`app_model::json`) on arbitrary bytes, as the settings files, a vault's
//! saved searches and browser items and the instance line give it. Must
//! never panic or hang. What it takes is written back compact and pretty;
//! both read back to the same value and write the same bytes again, and the
//! reader that refuses repeated keys takes only what the other takes.
#![no_main]

use app_model::json::{self, Value};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let unique = json::from_slice_unique(data);
    let Ok(value) = json::from_slice(data) else {
        assert!(unique.is_err(), "the strict reader takes no more");
        return;
    };
    if let Ok(strict) = unique {
        assert_eq!(strict, value, "both readers agree");
    }
    for text in [json::to_string(&value), json::to_string_pretty(&value)] {
        let again: Value = json::from_str(&text).expect("App's output reads back");
        assert_eq!(again, value, "the same value");
        assert_eq!(json::to_string(&again), json::to_string(&value));
    }
});
