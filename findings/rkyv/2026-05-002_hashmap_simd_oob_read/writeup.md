---

id: "002_rkyv_hashmap_simd_oob_read"
finding_number: 2
status: PUBLIC-DISCLOSED
status_date: 2026-05-11
severity: medium
target_project: rkyv
target_version: 0.8.16
discovered: 2026-05-11
disclosed: 2026-05-11
cve: null
bug_class: oob-read
component: hashmap-simd-probe
api_surface: safe
affected_file: rkyv/src/collections/swiss_table/table.rs
affected_function: control_raw
affected_line: 97
tags: [security, rkyv, oob-read, simd, rust]
disclosure_policy: rkyv SECURITY.md (AI-assisted findings skip embargo)
---

# Finding 002 — rkyv 0.8.16: SIMD OOB read past input buffer in HashMap deserialization

**Status: PUBLIC-DISCLOSED — filed in public tracker per rkyv SECURITY.md update**
**Discovered: 2026-05-11 (~30 min after Finding 001)**
**Discoverer: Mario Feter / SecureLoop**

---

## Summary

`rkyv::from_bytes::<HashMap<String, Vec<u32>>, Error>(data)` performs a 16-byte
SIMD load (`_mm_loadu_si128`) at exactly the end of the input buffer, reading
16 bytes past the last valid input byte.

This is **distinct from Finding 001** (different PC, different bug class):

- **Finding 001**: SEGV inside `ArchivedStringRepr::is_inline()` due to
  following an attacker-controlled offset to an unmapped page.
- **This finding (002)**: heap-buffer-overflow READ exactly 0 bytes after
  the user-provided input slice, inside an SSE2 16-byte unaligned load
  inlined into rkyv's HashMap validation/probe path.

ASAN report: `READ of size 16 at 0x..274` where the input was
`[0x..180, 0x..274)` — read starts exactly at the end of input.

## Severity

**Probably medium.** Same class as Finding 001:
- Pure OOB read at controlled distance (16 bytes past input end).
- Safe API contract violation (`from_bytes` is not allowed to read past the
  slice it was given).
- 16 bytes are arbitrary memory contents — info disclosure primitive.
- The SIMD-based hash-table probing is what most of rkyv 0.8 uses for
  HashMap; this is a hot path.

The seeded fuzzer found this in ~seconds. Without seeds, only Finding 001
was triggered in 30 min of cold fuzzing. Seed corpus moved the fuzzer into
the deeper validation paths immediately.

## Affected versions

- rkyv git HEAD `4a841456f348b9c8115ba4d9fda70332af3d69c5` ("Fix B-Tree
  maps not validating number of entries", 2026-05 timeframe).
- rkyv 0.8.16 release (latest on crates.io as of 2026-05-11) — same SIMD
  path. Confirmed reproducible.

## Reproducer

The 244-byte crash input is at
`findings/crashes/2026-05-11_rkyv_hashmap_simd_oob_read.bin` (NOT in git).

Hex preview:

```
00000000: a8f3 86da 834c c870 75e8 8bae 1fb9 7c00
00000010: 00ff 7981 c827 87cc 5e39 7059 34eb 6622
00000020: 076a 7c54 4262 3f40 ffff ffff ffff ffff
00000030: 009d ffff 0000 0000 0000 0000 0000 0000
... (244 bytes total)
```

Same harness as Finding 001:

```rust
use rkyv::{from_bytes, rancor::Error};
use std::collections::HashMap;

fuzz_target!(|data: &[u8]| {
    let _ = from_bytes::<HashMap<String, Vec<u32>>, Error>(data);
});
```

Build/run identical to Finding 001 (ASAN + debug-assertions).

## Symbolized backtrace

```
#0 __asan_memcpy  (interceptor)
#1 from_bytes_hashmap::_::__libfuzzer_sys_run
   ← inlined: _mm_loadu_si128
     core/src/../../stdarch/crates/core_arch/src/x86/sse2.rs:1335
#2 rust_fuzzer_test_input
...
```

The SSE2 load is inlined past the rkyv→harness boundary in addr2line's
view, but the location is unambiguous: a 128-bit unaligned load is being
issued against the input buffer's tail, with no pre-load bounds check.

## ASAN report (excerpt)

```
==91082==ERROR: AddressSanitizer: heap-buffer-overflow
on address 0x76a17e0e0274 at pc 0x5a2343a9bcab
READ of size 16 at 0x76a17e0e0274 thread T0

0x76a17e0e0274 is located 0 bytes after 244-byte region [0x76a17e0e0180,0x76a17e0e0274)
allocated by thread T0 here:
    #1 0x79917f0c3e43  (libstdc++.so.6+0xc3e43)   ← input vector alloc
```

The "allocated by" frame is libfuzzer's input buffer allocation — confirming
the OOB read is past the **user-controlled input slice**, not internal rkyv
scratch memory.

## Why it matters

Identical reasoning to Finding 001:

1. `from_bytes::<T, E>` is the safe entry. It must never read past its input.
2. SIMD-optimized HashMap probing reads in 16-byte chunks; the validator
   apparently does not pad/check the slice length before issuing the load.
3. 16 bytes of read past the input buffer is a controlled OOB read primitive.
4. Combined with a heap-spray of adjacent allocations, this can leak chosen
   secrets adjacent to the input — practical info disclosure.

## Already known?

Cross-checked the same way as Finding 001:
- **RustSec**: 3 advisories, none matching SIMD load past buffer end.
- **GitHub issues**: nothing on SIMD / SSE2 / OOB read in 2025-2026 windows.

## Recommended next steps

1. Identify the exact rkyv source line that emits this SIMD load. Likely
   `rkyv/src/collections/swiss_table/` or the validator there.
2. Minimize with `cargo fuzz tmin from_bytes_hashmap …`.
3. Bundle both findings 001 + 002 in a single email to [maintainer],
   since both are in the same harness and likely fixable together by adding
   length-pre-checks before reading representation bytes / issuing SIMD
   loads.
4. Continue fuzzing the other harnesses with seeds.

## Patch sketch (preliminary)

The deserializer probably needs an `if input.len() < REQUIRED_PROBE_BYTES`
fast-fail before entering the SIMD probe loop. Equivalent: round the input
length up to the 16-byte SIMD chunk and refuse anything shorter than the
declared table capacity × probe-group-size.
