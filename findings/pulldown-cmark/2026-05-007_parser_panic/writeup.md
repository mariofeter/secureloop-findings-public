---
id: "007_pulldown_cmark_parser_panic"
finding_number: 7
status: PUBLIC-DISCLOSED
status_date: 2026-05-19
severity: medium
target_project: pulldown-cmark
target_version: 0.13.3
discovered: 2026-05-12
discovered_by: SecureLoop rotator (autonomous, 3min fuzz)
disclosed: 2026-05-12
cve: null
github_issue: pulldown-cmark#1097
bug_class: reachable-panic
component: parser-state-machine
api_surface: safe
affected_repo: https://github.com/pulldown-cmark/pulldown-cmark
affected_file: pulldown-cmark/src/parse.rs
affected_function: next
affected_line: 2367
tags: [security, pulldown-cmark, reachable-panic, rust, markdown, dos]
disclosure_policy: coordinated — private disclosure 2026-05-12, fix PR #1096 by maintainer
---

# Finding 007 — pulldown-cmark 0.13.3: panic on `Option::unwrap()` in `parse.rs:2367` via crafted markdown input

**Status: PUBLIC-DISCLOSED 2026-05-19 — fix in PR #1096**
**Discovered: 2026-05-12 by SecureLoop rotator (autonomous, 3 minutes of fuzz from empty corpus)**

---

## Summary

`pulldown_cmark::Parser::new(s)` followed by event iteration (any
`collect` / `for` / consume) panics on crafted markdown input. The panic
occurs in `parse.rs:2367` at an `Option::unwrap()` site inside the
parser state machine.

This is a **reachable panic from a safe public API**. Any application
that renders user-provided markdown without explicit panic isolation
(`catch_unwind`) crashes on this input. Affected use cases include:
- Web servers rendering markdown comments / posts
- CLI tools processing markdown files
- Static-site generators (mdBook, zola, hugo-via-pulldown, etc.)

## Severity

**Medium** — DoS reachable from safe code via the documented public API.
Not memory corruption, but production-grade impact on any markdown-rendering
service that accepts user input.

## Affected versions

- pulldown-cmark 0.13.3 (crates.io, latest as of 2026-05-12)

## Reproducer

Harness:

```rust
#![no_main]
use libfuzzer_sys::fuzz_target;
use pulldown_cmark::Parser;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _: Vec<_> = Parser::new(s).collect();
    }
});
```

Crash input (1770 bytes) at `repro.bin`. First 64 bytes:

```
00000000: 323c 2d0b 7a5f 0a2d 0a2d 0a0a 2d0a 0a2d  2<-.z_.-.-..-..-
00000010: 100a 2d0a 0a2d 0a0a 2d10 0a0a 2d0a 0a2d  ..-..-..-...-..-
00000020: 0a0a 2d0a 0a0a 320a 0a2d 0a0a 2d0a 0a10  ..-...2..-..-...
00000030: 0a2d 0a60 5b31 5b5d 5b0a 3100 0000 0a1f  .-.`[1[][.1.....
```

Pattern: many `-` heading-underline tokens interleaved with `[1[][`
link-like sequences and newlines. The state machine reaches an
`Option::None` it expected to be `Some(...)`.

Build:

```bash
RUSTFLAGS='-Cpasses=sancov-module -Cllvm-args=-sanitizer-coverage-level=3 \
-Cllvm-args=-sanitizer-coverage-inline-8bit-counters \
-Cllvm-args=-sanitizer-coverage-pc-table \
-Cllvm-args=-sanitizer-coverage-trace-compares \
-Zsanitizer=address' \
cargo +nightly build --release -Zbuild-std --target x86_64-unknown-linux-gnu
```

Run:

```bash
ASAN_OPTIONS=abort_on_error=0:halt_on_error=0:exitcode=0:detect_leaks=0:handle_abort=0 \
  ./target/x86_64-unknown-linux-gnu/release/parser_run_strwrap repro.bin
```

## Panic trace

```
thread '<unnamed>' panicked at pulldown-cmark-0.13.3/src/parse.rs:2367:37:
called `Option::unwrap()` on a `None` value
==ERROR: libFuzzer: deadly signal
```

## Discovery context

This is the first finding produced by SecureLoop's autonomous rotator
(no human picked the target — `discover_crates.py` + `infer_hints_v2.py`
chain added pulldown-cmark to the queue). Time-to-crash: **3 minutes**
from an empty corpus.

## Recommended fix area

Inspect `parse.rs:2367` — the call site of `Option::unwrap()`. Likely
fixes:
1. Replace `unwrap()` with proper error path (`?` / explicit handling)
2. Validate the invariant the unwrap relies on earlier in the parser
3. If invariant is structural, add `debug_assert!` + treat the unwrap as
   genuine bug (state machine reached unexpected state)
