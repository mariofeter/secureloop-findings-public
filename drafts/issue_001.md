Title: Heap-buffer-overflow / OOB read in `from_bytes::<HashMap<String, _>>` via crafted ArchivedString pointer

---

> **Discovered by [SecureLoop](https://github.com/mariofeter/secureloop-findings-public)** — ML-guided fuzzing orchestrator with closed-loop learning. Published per [rkyv SECURITY.md](https://github.com/rkyv/rkyv/blob/master/SECURITY.md) (AI-assisted findings skip embargo). Track record + methodology: [secureloop-findings-public](https://github.com/mariofeter/secureloop-findings-public).

**Affected**: rkyv 0.8.16 (also reproduces on git HEAD `4a841456`)
**API surface**: safe (`rkyv::from_bytes` / `rkyv::access`)
**Class**: CWE-125 — out-of-bounds read
**Severity**: medium
**Tool**: SecureLoop (ML scorer + auto-generated harness)

## Summary

`rkyv::from_bytes::<HashMap<String, Vec<u32>>, Error>(data)` triggers an out-of-bounds read on a crafted input. Reproducer attached. Stack trace below.

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

Run with the attached reproducer ([`repro.bin`](https://github.com/mariofeter/secureloop-findings-public/raw/master/findings/rkyv/2026-05-001_hashmap_string_oob_read/repro.bin)):
```
ASAN_OPTIONS=abort_on_error=0:halt_on_error=0:exitcode=0:detect_leaks=0:handle_abort=0 \
  ./target/x86_64-unknown-linux-gnu/release/repro repro.bin
```

## Sanitizer trace (top frames)

```
  #0 ArchivedStringRepr::is_inline  (rkyv/src/string/repr.rs:53)
  #1 ArchivedStringRepr::as_ptr     (rkyv/src/string/repr.rs:70)
  #2 ArchivedHashTable::lookup
  #3 from_bytes deserialization path
```

## Suggested fix area

Containment check on `&ArchivedStringRepr` BEFORE reading any byte from it inside the HashMap entry validator. The current sequence resolves a String pointer via offset, then dereferences without verifying the resulting address is within the buffer bounds.

## Full writeup

[2026-05-001_hashmap_string_oob_read](https://github.com/mariofeter/secureloop-findings-public/blob/master/findings/rkyv/2026-05-001_hashmap_string_oob_read/writeup.md)

## About SecureLoop

[SecureLoop](https://github.com/mariofeter/secureloop-findings-public) is an experimental ML-guided vulnerability
discovery system. The pipeline that found this issue:

1. **GNN scorer** ranked rkyv functions by predicted vulnerability likelihood
   (trained on rustsec.json — paired vuln/patch corpus). Top picks for this
   crate included `access_pos_unchecked`, `as_ptr_raw`, `deserialize_shared`,
   and the swiss_table/string repr surfaces — exactly the regions this bug
   lives in.
2. **Auto-harness generator** parsed the public API signature and emitted a
   targeted `fuzz_target!` harness without human-written boilerplate.
3. **libFuzzer + ASAN + sancov** at `-Cinstrumented` ran the harness until
   the crash surfaced.
4. **Closed-loop retrain** — the resulting finding feeds back into the
   scorer's next training round.

Track record + methodology: [https://github.com/mariofeter/secureloop-findings-public](https://github.com/mariofeter/secureloop-findings-public).
