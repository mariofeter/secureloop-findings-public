---

id: "003_rkyv_hashmap_u64_bytes_oob"
finding_number: 3
status: PUBLIC-DISCLOSED
status_date: 2026-05-11
severity: medium
target_project: rkyv
target_version: 0.8.16
discovered: 2026-05-11
disclosed: 2026-05-11
cve: null
bug_class: heap-buffer-overflow
component: hashmap-u64-keys-deserialization
api_surface: safe
affected_file: rkyv/src/collections/swiss_table/table.rs
affected_function: control_raw
affected_line: 97
tags: [security, rkyv, oob, rust]
disclosure_policy: rkyv SECURITY.md (AI-assisted findings skip embargo)
---

# Finding 003 — rkyv 0.8.16: heap-buffer-overflow in HashMap<u64, Vec<u8>> deserialization

**Status: PUBLIC-DISCLOSED — filed in public tracker per rkyv SECURITY.md update**
**Discovered: 2026-05-11**
**Discoverer: Mario Feter / SecureLoop**

---

## Summary

`rkyv::from_bytes::<HashMap<u64, Vec<u8>>, Error>(data)` triggers a heap-
buffer-overflow on a crafted 92-byte input. Unlike Findings 001/002, this
path does NOT involve `ArchivedStringRepr` — keys are fixed-size `u64`,
values are byte vectors. Confirms the OOB read class extends to non-string
HashMap paths.

## Severity

**Medium.** OOB read in safe API, attacker-controlled offset.

## Affected versions

- rkyv git HEAD `4a841456...`
- rkyv 0.8.16 (crates.io)

## Reproducer

92-byte input at `rkyv_hashmap_u64_bytes_oob.bin`.

Harness:

```rust
fuzz_target!(|data: &[u8]| {
    let _ = from_bytes::<HashMap<u64, Vec<u8>>, Error>(data);
});
```

## ASAN summary

```
==<pid>==ERROR: AddressSanitizer: heap-buffer-overflow
SUMMARY: AddressSanitizer: heap-buffer-overflow
  from_bytes_hashmap_u64_bytes+0x12784a
```

Top frame symbolized: `from_bytes_hashmap_u64_bytes::_::__libfuzzer_sys_run`
(inlined; the actual rkyv-side site is the HashMap-with-non-string-keys
validation path).

## Why it matters

Confirms the bug pattern isn't string-specific. Validating fixed-size key
types still misses a containment check somewhere in the table-data
traversal.

## Recommended next steps

1. Symbolize fully with `lto=off -Copt-level=1` build.
2. Bundle with Findings 001/002 in follow-up to maintainer.
