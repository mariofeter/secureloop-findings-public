---

id: "006_rkyv_swiss_table_unchecked_assert"
finding_number: 6
status: PUBLIC-DISCLOSED
status_date: 2026-05-11
severity: high
target_project: rkyv
target_version: 0.8.16
discovered: 2026-05-11
disclosed: 2026-05-11
cve: null
bug_class: missing-validation-soundness
component: swiss-table-control-raw
api_surface: safe
affected_file: rkyv/src/collections/swiss_table/table.rs
affected_function: control_raw
affected_line: 97
tags: [security, rkyv, soundness, debug-assert, rust]
disclosure_policy: rkyv SECURITY.md (AI-assisted findings skip embargo)
---

# Finding 006 — rkyv 0.8.16: silent UB in `control_raw` (release builds skip the debug_assert)

**Status: PUBLIC-DISCLOSED — filed in public tracker per rkyv SECURITY.md update**
**Discovered: 2026-05-11**
**Discoverer: Mario Feter / SecureLoop**

---

## Summary

`rkyv::access::<ArchivedHashMap<ArchivedString, ArchivedString>, Error>(data)`
on a 132-byte crafted input panics in debug builds at:

```
rkyv/src/collections/swiss_table/table.rs:97
panic: assertion failed: unsafe { !(*this).is_empty() }
```

The panic happens inside `unsafe fn control_raw`:

```rust
unsafe fn control_raw(this: *mut Self, index: usize) -> *const u8 {
    debug_assert!(unsafe { !(*this).is_empty() });   // <-- only in debug
    let ptr = unsafe { RawRelPtr::as_ptr_raw(ptr::addr_of_mut!((*this).ptr)) };
    unsafe { ptr.cast::<u8>().add(index) }
}
```

This is a `debug_assert!`, which is **compiled out in release builds**.
When the precondition is violated by attacker-controlled input:
- Debug build: panic (what cargo-fuzz catches today)
- **Release build: silent UB** — `as_ptr_raw` runs over an
  `ArchivedHashTable` that is supposed-to-be-non-empty but isn't; the
  relative pointer it follows is uninitialized / garbage; the
  subsequent `.add(index)` produces a wild pointer; the caller reads
  through it.

The validator is supposed to ensure `is_empty()` is false before this
path is reached. **It does not in this input.** That's the bug.

## Severity

**High.** Pure soundness violation, reachable via the **safe API**
(`access` is documented as a safe entry point). In release builds the
guard is absent; in debug it surfaces as a panic. Real-world impact:
arbitrary-pointer read primitive triggered by 132 bytes of input.

This is distinct from Findings 001-005 (which manifested as
ASAN-detected memory errors); this one is a **missing validation in
the validator itself** — the validator returns Ok for an input that
violates the invariant that `control_raw` relies on.

## Affected versions

- rkyv git HEAD `4a841456...`
- rkyv 0.8.16 (crates.io)

## Reproducer

132-byte input at `rkyv_swiss_table_assert.bin`.

Harness:

```rust
use rkyv::{access, rancor::Error, collections::swiss_table::ArchivedHashMap,
           string::ArchivedString};

fuzz_target!(|data: &[u8]| {
    let _ = access::<ArchivedHashMap<ArchivedString, ArchivedString>, Error>(data);
});
```

Note: this uses `access` (zero-copy validation only, no deserialize
pool), which **isolates the bug to the validator**, not to the
deserialize path that Findings 004/005 hit. The previous UAFs and this
soundness break point at the same component (HashMap/SwissTable
validation in `rkyv::collections::swiss_table`).

## Stack trace (symbolized)

```
panic at rkyv/src/collections/swiss_table/table.rs:97
  -> access_hashmap_str_str::_::__libfuzzer_sys_run
  -> rust_fuzzer_test_input ...
```

The panic site **is** the rkyv source — no inlining ambiguity here.

## Why it matters

`debug_assert!` is the wrong guard for a precondition that protects
`unsafe` code. Every release build of rkyv is exposed; the assertion
that "fires in fuzzing" is purely an artifact of cargo-fuzz turning
debug_assertions on. Real consumers do not.

This is one of those bugs where the fix is also unambiguous: either
replace `debug_assert!` with `assert!`, or — better — make the
validator reject inputs that would trip this precondition so the
unsafe function's caller doesn't need to re-check.

## Recommended fix

In `table.rs:97`:

```rust
unsafe fn control_raw(this: *mut Self, index: usize) -> *const u8 {
    assert!(unsafe { !(*this).is_empty() });   // release-active guard
    ...
}
```

OR (preferred, better separation of concerns) audit the
`ArchivedHashTable` validator to reject empty-but-claims-non-empty
shapes so `control_raw` callers actually meet the precondition.

## Already known?

- RustSec advisories cross-checked, no match.
- The latest rkyv commit (`4a841456 Fix B-Tree maps not validating
  number of entries`) is in the SAME area (collections validation).
  Suggests this is an active maintenance hotspot — bundled disclosure
  is timely.
