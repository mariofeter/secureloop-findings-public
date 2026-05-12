---
id: "008_rkyv_hashmap_archivedstring_deserialize_segv"
finding_number: 8
status: PUBLIC-DISCLOSED
status_date: 2026-05-12
severity: medium-high
target_project: rkyv
target_version: 0.8.16
discovered: 2026-05-12
disclosed: 2026-05-12
cve: null
bug_class: oob-read
component: hashmap-value-deserialize
api_surface: safe
affected_file: rkyv/src/string/mod.rs
affected_function: <rkyv::string::ArchivedString as rkyv::Deserialize>::deserialize
tags: [security, rkyv, oob-read, segv, rust]
disclosure_policy: rkyv SECURITY.md (AI-assisted findings skip embargo)
related_issues:
  - "rkyv#663 (same family — unvalidated ArchivedString pointer, different value-type)"
  - "rkyv#666 (UAF in same function, different trigger path via derive(Archive))"
---

# Finding 008 — rkyv 0.8.16: SEGV in `ArchivedString::deserialize` for `HashMap<String, String>`

**Status: PUBLIC-DISCLOSED — filed in public tracker per rkyv SECURITY.md**
**Discovered: 2026-05-12 — autonomous discovery by SecureLoop rotator**
**Discoverer: Mario Feter / SecureLoop**

---

## Summary

`rkyv::from_bytes::<HashMap<String, String>, Error>(data)` triggers a
SEGV (READ on unknown address) on a crafted 128-byte input. The crash
occurs **after** `ArchivedHashTable::control_iter` has begun walking the
table — the SwissTable boundary validations succeed — but when the
implementation tries to dereference an `ArchivedString` value pointer
to deserialize the entry, the pointer points to unmapped memory.

This sits in the same family as rkyv#663 and rkyv#666 — all three
trace back to `ArchivedString` pointers being dereferenced without a
containment check against the input buffer. The differences are in
*where* the failure surfaces:

| | rkyv#663 | rkyv#666 | This finding (008) |
|---|---|---|---|
| Trigger type | `HashMap<String, Vec<u32>>` | `#[derive(Archive)] struct { String, … }` | `HashMap<String, String>` |
| Failing frame | `ArchivedStringRepr::is_inline` / `as_ptr` | `ArchivedString::deserialize` | `ArchivedString::deserialize` |
| Phase | Initial table validation | Post-validation deserialize of struct fields | Per-entry value deserialize (post `control_iter`) |
| ASAN class | OOB read / heap-buffer-overflow | heap-use-after-free | SEGV (read of unmapped addr) |
| Root family | unvalidated ArchivedString pointer | unvalidated ArchivedString pointer | unvalidated ArchivedString pointer |

Same root cause family. May be fixed by the same patch covering bounds
checks on `ArchivedString` pointers across both the table-validation
and per-entry-value paths.

## Severity

**Medium-high.** CWE-125 (out-of-bounds read) via safe API on
attacker-controlled bytes. DoS for any crate downstream that calls
`rkyv::from_bytes::<HashMap<String, _>, _>` on untrusted input — common
pattern for caches, network protocols, on-disk indices. Not a write
primitive, but service-killing on any deployed parser.

## Affected versions

- rkyv 0.8.16 (crates.io). Reproduces deterministically (20/20 runs).

## Reproducer

Harness:
```rust
#![no_main]
use libfuzzer_sys::fuzz_target;
use std::collections::HashMap;
use rkyv::rancor::Error;

fuzz_target!(|data: &[u8]| {
    let _ = rkyv::from_bytes::<HashMap<String, String>, Error>(data);
});
```

Build:
```
RUSTFLAGS='-Cpasses=sancov-module -Cllvm-args=-sanitizer-coverage-level=3 \
-Cllvm-args=-sanitizer-coverage-inline-8bit-counters \
-Cllvm-args=-sanitizer-coverage-pc-table \
-Cllvm-args=-sanitizer-coverage-trace-compares \
-Zsanitizer=address' \
cargo +nightly build --release -Zbuild-std --target x86_64-unknown-linux-gnu
```

Run with the attached reproducer (`repro.bin`, 128 bytes,
sha1 `82dd7ed732052f8e08dabddf8aac7fac61076fb9`):
```
ASAN_OPTIONS=abort_on_error=0:halt_on_error=0:exitcode=0:detect_leaks=0:handle_abort=0 \
  ./target/x86_64-unknown-linux-gnu/release/repro repro.bin
```

## Sanitizer trace (top frames)

```
==<pid>==ERROR: AddressSanitizer: SEGV on unknown address
==<pid>==The signal is caused by a READ memory access.
  #0 <rkyv::string::ArchivedString as rkyv::traits::Deserialize<
        alloc::string::String,
        rancor::Strategy<rkyv::de::pooling::alloc::Pool, rancor::Error>
     >>::deserialize
  #1 <rkyv::collections::swiss_table::table::ArchivedHashTable<
        rkyv::collections::util::Entry<
            rkyv::string::ArchivedString,
            rkyv::string::ArchivedString>
     >>::control_iter
  #2 rkyv::from_bytes::<HashMap<String, String>, Error>
```

## Alternate reproducer (Vec wrapper, same root cause)

A second seed surfaces the same bug family from a different container
shape — `Vec<HashMap<String, String>>`. Same failing function on frame,
but the Vec wrapper routes through `DeserializeUnsized` first, and the
SEGV materialises inside `__asan_memcpy` rather than the bare load.

Attached as `repro_alt_vec_wrapper.bin` (564 bytes,
sha1 `a1e59c1378dbff39d3311d03f2771a4f3ffccda2`). Reproduces 3/3 against
a `from_bytes::<Vec<HashMap<String, String>>, Error>` harness.

Top frames for the alt repro:
```
  #0 __asan_memcpy
  #1 (inlined slice load)
  #2 <ArchivedString as Deserialize>::deserialize
  #3 <[ArchivedHashMap<ArchivedString, ArchivedString>] as DeserializeUnsized<…>>::deserialize_unsized
  #4 rkyv::from_bytes::<Vec<HashMap<String, String>>, Error>
```

Documenting in one issue — the underlying fix should cover both paths.

## Suggested fix area

Before dereferencing an `ArchivedString` repr inside a HashMap's value
slot, the deserialize implementation must validate that the resolved
pointer address is fully contained within the original buffer bounds.
The fix likely belongs in `<ArchivedString as Deserialize>::deserialize`
(or its underlying `as_ptr` helper) — the same surface area as the
proposed fix for #663, but applied also to the per-entry
value-deserialize codepath that runs after table-level validation.

## Why it matters

`from_bytes::<T, E>` is contractually "validation succeeds OR returns
an error" — a SEGV violates that contract. The `bytecheck`-driven
validation is the reason users pick `rkyv::from_bytes` over
`unsafe { access_unchecked }`; if validation lets an OOB read slip
through, that value proposition weakens.

## Discovery context

Autonomous discovery by SecureLoop's rotator. The bug surfaced first as
an alt-shape crash on `from_bytes_vec_hashmap_string_string`, then was
reproduced cleanly on the simpler `from_bytes_hashmap_string_string`
harness during triage. The simpler reproducer is filed as the primary
attachment; the Vec wrapper sits in the same writeup as an alt repro
because the failure path is the same.
