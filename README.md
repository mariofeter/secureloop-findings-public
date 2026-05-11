# SecureLoop — Public Findings

Track record of vulnerabilities discovered by **SecureLoop**, an ML-guided
vulnerability discovery system with closed-loop learning.

> **Method**: rank functions by vulnerability likelihood (GNN scorer) → auto-generate
> targeted fuzz harnesses → run with sanitizer instrumentation → triage crashes
> → feed labeled findings back into scorer retraining.

This repository publishes findings **after** they've been filed in the upstream
project's public tracker, per each upstream's security policy.

---

## What's here

Each finding lives at `findings/<crate>/<id>/`:

- `writeup.md` — sanitized technical writeup (summary, repro, ASAN trace,
  severity, recommended fix area)
- `repro.bin` — reproducer input bytes
- *(optional)* `trace.txt` — full sanitizer output

Sanitization removes only maintainer contact info and absolute filesystem paths.
All technical content is preserved.

## How to verify a finding

Each writeup describes the affected version, harness shape, and how to
reproduce. Quickstart for an rkyv finding:

```rust
// fuzz_targets/repro.rs (libfuzzer-sys)
#![no_main]
use libfuzzer_sys::fuzz_target;
use std::collections::HashMap;
use rkyv::rancor::Error;
fuzz_target!(|data: &[u8]| {
    let _ = rkyv::from_bytes::<HashMap<String, Vec<u32>>, Error>(data);
});
```

```bash
cargo +nightly build --release -Zbuild-std --target x86_64-unknown-linux-gnu
ASAN_OPTIONS=abort_on_error=0:halt_on_error=0:exitcode=0:detect_leaks=0:handle_abort=0 \
  ./target/x86_64-unknown-linux-gnu/release/repro \
  findings/rkyv/<id>/repro.bin
```

For each finding the writeup gives the exact type instantiation and build
profile needed.

## Disclosure policy

Findings are disclosed according to the upstream project's policy. For
**rkyv 0.8.16** specifically: [rkyv SECURITY.md](https://github.com/rkyv/rkyv/blob/master/SECURITY.md)
explicitly directs AI-assisted findings to skip the responsible disclosure
window and file directly in the issue tracker. We follow that policy.

For projects without an AI-specific policy, SecureLoop follows a standard
90-day coordinated disclosure timeline before publishing.

## About SecureLoop

SecureLoop is an experimental ML-guided fuzzing orchestrator. The core
components are:

- **GNN-based vulnerability scorer** trained on a labeled Rust security
  advisory corpus (rustsec.json, ~1500 paired vuln/patch samples)
- **Auto-harness generator** that walks ML top-K function signatures and
  emits cargo-fuzz / libfuzzer-sys harnesses
- **Closed-loop learning** — each new finding becomes a training sample
  for the next retrain round

The orchestrator's source repository is not yet public. This repository
publishes the findings only.

## Citation

If you reference this work:

```
SecureLoop ML-guided vulnerability discovery (M. Feter, 2026).
https://github.com/mariofeter/secureloop-findings-public
```

## Contact

Issues with the findings themselves: open an issue in this repo.
For coordination on a new disclosure: contact via the upstream project's
security channel.
