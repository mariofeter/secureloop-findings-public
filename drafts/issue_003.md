Title: OOB read via `u64::from_le_bytes` on crafted ArchivedHashTable bucket offset

---

**Affected**: rkyv 0.8.16 (also reproduces on git HEAD `4a841456`)
**API surface**: safe (`rkyv::from_bytes` / `rkyv::access`)
**Class**: CWE-125 — out-of-bounds read (8-byte read past validated region)
**Severity**: medium

## Summary

`rkyv::from_bytes::<HashMap<String, Vec<u32>>, Error>(data)` triggers a out-of-bounds read (8-byte read past validated region) on a crafted input. Reproducer
attached. Stack trace below.

## Reproducer

Harness:
```rust
#![no_main]
use libfuzzer_sys::fuzz_target;
use std::collections::HashMap;
use rkyv::rancor::Error;

fuzz_target!(|data: &[u8]| {
    let _ = rkyv::from_bytes::<HashMap<String, Vec<u32>>, Error>(data);
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

Run with the attached reproducer ([`repro.bin`](https://github.com/mariofeter/secureloop-findings-public/raw/master/findings/rkyv/2026-05-003_hashmap_u64_bytes_oob/repro.bin)):
```
ASAN_OPTIONS=abort_on_error=0:halt_on_error=0:exitcode=0:detect_leaks=0:handle_abort=0 \
  ./target/x86_64-unknown-linux-gnu/release/repro repro.bin
```

## Sanitizer trace (top frames)

```
  #0 u64::from_le_bytes reading bucket data
  #1 ArchivedHashTable::control_raw  (table.rs:97)
  #2 Entry validator following resolved relative pointer
```

## Suggested fix area

Pointer is followed without bounds-checking the 8-byte read of the bucket payload. Validate `ptr + 8 <= buf.end()` (or equivalent containment) before the `u64::from_le_bytes` read.

## Full writeup

[2026-05-003_hashmap_u64_bytes_oob](https://github.com/mariofeter/secureloop-findings-public/blob/master/findings/rkyv/2026-05-003_hashmap_u64_bytes_oob/writeup.md)

## Provenance

Discovered with the assistance of AI-driven fuzzing tooling (SecureLoop — ML-guided
harness generation + closed-loop learning). Filing per
[rkyv SECURITY.md](https://github.com/rkyv/rkyv/blob/master/SECURITY.md), which
directs AI-assisted findings to skip the responsible disclosure window.
