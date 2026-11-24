//! E6-S6 (SR-07, LD-133): the core the Mac app links uses the zeroing
//! allocator. This binary links larsal-ffi as the app does, so the global
//! allocator here is the one in the static library.

#[test]
fn the_linked_core_zeroes_freed_blocks() {
    // Linked like the app, through an export.
    assert!(!larsal_ffi::core_version().is_empty());
    // Control: straight through the system allocator the bytes survive.
    assert!(larsal_platform::memory::marker_survives_free(false));
    assert!(!larsal_platform::memory::marker_survives_free(true));
}
