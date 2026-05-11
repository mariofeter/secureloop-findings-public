Title: Heap-use-after-free in `ArchivedString::deserialize` for `#[derive(Archive)]` struct with String fields

---

**Affected**: rkyv 0.8.16 (also reproduces on git HEAD `4a841456`)
**API surface**: safe (`rkyv::from_bytes` / `rkyv::access`)
**Class**: CWE-416 — use-after-free
**Severity**: high

## Summary

`rkyv::from_bytes::<ComplexBag, Error>(data)` triggers a use-after-free on a crafted input. Reproducer
attached. Stack trace below.

## Reproducer

Harness:
```rust
#![no_main]
use libfuzzer_sys::fuzz_target;
use std::collections::HashMap;
use rkyv::rancor::Error;

#[derive(rkyv::Archive, rkyv::Deserialize, rkyv::Serialize)]
struct ComplexBag {
    names: Vec<String>,
    counters: Option<HashMap<String, u32>>,
    payload: Box<Vec<u64>>,
    flag: bool,
}

fuzz_target!(|data: &[u8]| {
    let _ = rkyv::from_bytes::<ComplexBag, Error>(data);
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

Run with the attached reproducer ([`repro.bin`](https://github.com/mariofeter/secureloop-findings-public/raw/master/findings/rkyv/2026-05-005_complex_struct_uaf/repro.bin)):
```
ASAN_OPTIONS=abort_on_error=0:halt_on_error=0:exitcode=0:detect_leaks=0:handle_abort=0 \
  ./target/x86_64-unknown-linux-gnu/release/repro repro.bin
```

## Sanitizer trace (top frames)

```
  #0 <ArchivedString as Deserialize<String, ...>>::deserialize (rkyv/src/impls/alloc/string.rs:39)
  #1 rkyv::de::pooling::alloc::Pool allocation / release path
  #2 Vec<String> or HashMap<String, _> entry deserialize loop
```

## Suggested fix area

UAF on deserialize fast path of any Rust struct that has a `String` field. The deserialize-side pool / error path appears to release memory while `ArchivedString::deserialize` still holds a pointer into the input buffer. Wide blast radius — affects every `#[derive(Archive)]` user.

## Full writeup

[2026-05-005_complex_struct_uaf](https://github.com/mariofeter/secureloop-findings-public/blob/master/findings/rkyv/2026-05-005_complex_struct_uaf/writeup.md)

## Provenance

Discovered with the assistance of AI-driven fuzzing tooling (SecureLoop — ML-guided
harness generation + closed-loop learning). Filing per
[rkyv SECURITY.md](https://github.com/rkyv/rkyv/blob/master/SECURITY.md), which
directs AI-assisted findings to skip the responsible disclosure window.
