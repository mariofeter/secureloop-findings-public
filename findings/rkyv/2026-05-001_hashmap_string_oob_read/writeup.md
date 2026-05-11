---

id: "001_rkyv_hashmap_string_oob_read"
finding_number: 1
status: PUBLIC-DISCLOSED
status_date: 2026-05-11
severity: medium
target_project: rkyv
target_version: 0.8.16
discovered: 2026-05-11
disclosed: 2026-05-11
cve: null
bug_class: oob-read
component: hashmap-string-deserialization
api_surface: safe
affected_file: rkyv/src/string/repr.rs
affected_function: as_ptr
affected_line: 70
tags: [security, rkyv, oob-read, rust]
disclosure_policy: rkyv SECURITY.md (AI-assisted findings skip embargo)
---

# Finding 001 — rkyv 0.8.16: OOB read in HashMap<String, _> deserialization (safe API)

**Status: PUBLIC-DISCLOSED — filed in public tracker per rkyv SECURITY.md update**
**Discovered: 2026-05-11**
**Discoverer: Mario Feter / SecureLoop**

---

## Summary

`rkyv::from_bytes::<HashMap<String, Vec<u32>>, Error>(data)` — the documented
**safe deserialization API** — performs an out-of-bounds read on attacker-
controlled bytes before validation rejects the input.

Under cargo-fuzz default build (release + ASAN + `-Cdebug-assertions`), this
manifests as a **SEGV / heap-buffer-overflow**. Under plain `cargo build
--release` (no ASAN, no asserts), the function returns `Err(...)` — the OOB
read silently succeeds and the validation eventually fails on the wrong path.

The read happens in `rkyv::string::repr::ArchivedStringRepr::is_inline()`
(`rkyv/src/string/repr.rs:53`), which performs an unchecked union read to
decide between the inline and out-of-line String representation. With a
crafted `HashMap<String, _>` archive, the key's `ArchivedString` pointer
lands at an unmapped address; reading `bytes[0]` segfaults.

## Severity

**Probably medium.** Pure soundness violation in safe Rust:
- Read primitive at arbitrary attacker-controlled address (not write).
- Could enable information disclosure (timing-leak based) or chain with other
  bugs.
- Cannot be triggered by `access_unchecked` only — happens via `from_bytes`,
  which is the documented safe entry point.

Not RCE on its own.

## Affected versions

- rkyv git HEAD at commit `4a841456f348b9c8115ba4d9fda70332af3d69c5`
  ("Fix B-Tree maps not validating number of entries", 2026-05 timeframe)
- rkyv 0.8.16 (crates.io release, latest as of 2026-05-11) — same code path
  in repr.rs:53. Confirmed: crash present under debug-assertions+ASAN, also
  present under plain release as a silent OOB read returning `Err`.

## Reproducer

The 124-byte input is at `crashes/2026-05-11_rkyv_hashmap_string_oob_read.bin`
(NOT in git). Hex preview:

```
00000000: 7156 d8b1 018b c59d 342f d414 38d4 56a3
00000010: 9461 efc1 f0ba 0025 ffff 0000 0000 0000
00000020: 0000 ffff ffff ff90 ffff ff03 0000 0000
00000030: 0000 0000 0000 0000 0000 0000 0000 00ff
00000040: 266e 1d73 ff26 6e1d 73ff ffff f7ff e2e2
00000050: e2e2 e2e2 e2e2 e2e2 e2e2 e2e2 e2e2 e2ff
00000060: ffff ffff ffff ffff ffff ffff ffff ff00
00000070: e0ff ffff 0400 0000 0500 0000
```

Minimum harness:

```rust
use rkyv::{from_bytes, rancor::Error};
use std::collections::HashMap;

fn main() {
    let data = std::fs::read("crash.bin").unwrap();
    let _ = from_bytes::<HashMap<String, Vec<u32>>, Error>(&data);
}
```

Build/run:

```bash
RUSTFLAGS="-Z sanitizer=address -C debug-assertions" \
  cargo +nightly run --release --target x86_64-unknown-linux-gnu
```

Expected: AddressSanitizer SEGV on read at unmapped address; PC inside
`ArchivedStringRepr::is_inline` (repr.rs:53).

## Symbolized backtrace

```
#0 ArchivedStringRepr::is_inline   rkyv/src/string/repr.rs:53
#1 (inlined) String validation / pointer follow inside HashMap entry
#2 rust_fuzzer_test_input            libfuzzer-sys-0.4.12/src/lib.rs:276
#3 std::panicking::catch_unwind::do_call
#4 __rust_try
#5 LLVMFuzzerTestOneInput
#6 fuzzer::Fuzzer::ExecuteCallback
...
```

Frames #0 in repr.rs:53 is the load. The HashMap path leading there is
inlined past addr2line resolution; need to rebuild with `lto=off` and
`-Copt-level=1` to recover the full call chain. To be added in a follow-up.

## Why it matters

1. The `from_bytes::<T, E>` function returns `Result<T, E>` — it is contract-
   ually "validation succeeds OR returns an error." A SEGV/OOB read violates
   that contract.
2. `bytecheck` is *the* reason to use rkyv over `unsafe { access_unchecked
   }`. If `from_bytes` reads OOB, the validation layer is unsound.
3. The bug class — reading representation bytes to dispatch on before
   checking the pointer's containment — is recurring in zero-copy frameworks
   (similar to historical issues in capnp, flatbuffers).

## Already known?

Cross-checked:
- **RustSec advisories for rkyv**: 3 known (RUSTSEC-2021-0054 / -2026-0001
  / -2026-0122). None match this signature (uninit memory / Arc-Rc-from_value
  UB / InlineVec-SerVec panic-safety). No HashMap or String repr advisory.
- **GitHub issues**: #639 (cross-platform discrepancy, closed) and #637
  (extra-data trailing bytes, closed not planned) are the closest. Neither
  matches.

## Recommended next steps

1. **Triage**: minimize the input with `cargo fuzz tmin from_bytes_hashmap
   ...` to get the smallest reproducer.
2. **Verify on stable release**: confirmed 0.8.16 also affected (sanity above).
3. **Inspect the validation path**: read `rkyv/src/collections/swiss_table/`
   and the `Archive` impl for `HashMap` to identify where the String pointer
   is followed before/without containment check.

5. Keep fuzzing the other 3 harnesses (access_vec_i32 / from_bytes_vec_i32 /
   from_bytes_nested) to surface related bugs.

## Patch sketch (preliminary, not verified)

The fix is likely to perform a containment check on `&ArchivedStringRepr`
BEFORE reading any byte from it inside the HashMap entry validator. The
current sequence appears to be:

1. Validate HashMap structure (count, capacity).
2. For each entry: read the key's `ArchivedString` repr.
3. Validate the String contents.

Step 2 must validate that the repr's *address* is fully contained within the
provided buffer before dereferencing it. The current code likely follows a
pointer from a prior validation step that resolved an offset, but doesn't
re-check the resulting address against the buffer bounds in this code path.
