Title: Heap-buffer-overflow in SIMD path of `ArchivedHashTable::control_raw` via crafted HashMap bucket count

---

> **Discovered by [SecureLoop](https://github.com/mariofeter/secureloop-findings-public)** — ML-guided fuzzing orchestrator with closed-loop learning. Published per [rkyv SECURITY.md](https://github.com/rkyv/rkyv/blob/master/SECURITY.md) (AI-assisted findings skip embargo). Track record + methodology: [secureloop-findings-public](https://github.com/mariofeter/secureloop-findings-public).

**Affected**: rkyv 0.8.16 (also reproduces on git HEAD `4a841456`)
**API surface**: safe (`rkyv::from_bytes` / `rkyv::access`)
**Class**: CWE-125 — out-of-bounds read (SIMD path)
**Severity**: medium
**Tool**: SecureLoop (ML scorer + auto-generated harness)

## Summary

`rkyv::from_bytes::<HashMap<String, Vec<u32>>, Error>(data)` triggers an out-of-bounds read (SIMD path) on a crafted input. Reproducer attached. Stack trace below.

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

Run with the attached reproducer ([`repro.bin`](https://github.com/mariofeter/secureloop-findings-public/raw/master/findings/rkyv/2026-05-002_hashmap_simd_oob_read/repro.bin)):
```
ASAN_OPTIONS=abort_on_error=0:halt_on_error=0:exitcode=0:detect_leaks=0:handle_abort=0 \
  ./target/x86_64-unknown-linux-gnu/release/repro repro.bin
```

## Sanitizer trace (top frames)

```
  #0 ArchivedHashTable::control_raw  (rkyv/src/collections/swiss_table/table.rs:97)
  #1 SIMD control byte scan (16-byte aligned load past buffer end)
  #2 HashMap lookup during from_bytes validation
```

## Suggested fix area

SIMD path reads 16 control bytes at once and assumes a 16-byte tail of valid memory. Crafted `bucket_count` that's just-below-a-multiple-of-16 reads past the legitimate end of the control byte region. Either pad the control region to 16-byte alignment OR clamp the SIMD chunk count to `bucket_count.div_ceil(16)`.

## Full writeup

[2026-05-002_hashmap_simd_oob_read](https://github.com/mariofeter/secureloop-findings-public/blob/master/findings/rkyv/2026-05-002_hashmap_simd_oob_read/writeup.md)
