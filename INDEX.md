# Findings Index

Pivot views over the published findings. Each row links to the writeup
and (where filed) the upstream issue tracker.

---

## By target crate

### rkyv 0.8.16 (6 findings)

| ID | Bug class | Severity | Status | Writeup | Upstream issue |
|---|---|---|---|---|---|
| 2026-05-001 | OOB read | medium | PUBLIC-DISCLOSED | [hashmap_string_oob_read](findings/rkyv/2026-05-001_hashmap_string_oob_read/writeup.md) | [rkyv#663](https://github.com/rkyv/rkyv/issues/663) |
| 2026-05-002 | OOB read | medium | PUBLIC-DISCLOSED | [hashmap_simd_oob_read](findings/rkyv/2026-05-002_hashmap_simd_oob_read/writeup.md) | [rkyv#664](https://github.com/rkyv/rkyv/issues/664) |
| 2026-05-003 | OOB read | medium | PUBLIC-DISCLOSED | [hashmap_u64_bytes_oob](findings/rkyv/2026-05-003_hashmap_u64_bytes_oob/writeup.md) | [rkyv#665](https://github.com/rkyv/rkyv/issues/665) |
| 2026-05-005 | UAF | high | PUBLIC-DISCLOSED | [complex_struct_uaf](findings/rkyv/2026-05-005_complex_struct_uaf/writeup.md) | [rkyv#666](https://github.com/rkyv/rkyv/issues/666) |
| 2026-05-006 | reachable assertion | high | PUBLIC-DISCLOSED | [swiss_table_unchecked_assert](findings/rkyv/2026-05-006_swiss_table_unchecked_assert/writeup.md) | [rkyv#667](https://github.com/rkyv/rkyv/issues/667) |
| 2026-05-008 | OOB read (SEGV) | medium-high | PUBLIC-DISCLOSED | [hashmap_archivedstring_deserialize_segv](findings/rkyv/2026-05-008_hashmap_archivedstring_deserialize_segv/writeup.md) | [rkyv#669](https://github.com/rkyv/rkyv/issues/669) |

### pulldown-cmark 0.13.3 (1 finding)

| ID | Bug class | Severity | Status | Writeup | Upstream issue |
|---|---|---|---|---|---|
| 2026-05-007 | reachable panic | medium | PUBLIC-DISCLOSED | [parser_panic](findings/pulldown-cmark/2026-05-007_parser_panic/writeup.md) | [pulldown-cmark#1097](https://github.com/pulldown-cmark/pulldown-cmark/issues/1097) |

---

## By bug class (CWE)

### CWE-125: Out-of-Bounds Read (4)
- `2026-05-001` rkyv — `ArchivedStringRepr::as_ptr` unchecked union read on crafted HashMap entry
- `2026-05-002` rkyv — SIMD-path OOB read in `ArchivedHashTable::control_raw`
- `2026-05-003` rkyv — OOB read via `u64::from_le_bytes` on crafted HashTable bucket
- `2026-05-008` rkyv — SEGV in `ArchivedString::deserialize` for `HashMap<String, String>` value-deref path

### CWE-416: Use-After-Free (1)
- `2026-05-005` rkyv — UAF in `ArchivedString::deserialize` on crafted struct with `String` field

### CWE-617: Reachable Assertion / Panic (2)
- `2026-05-006` rkyv — `debug_assert!` violation in `swiss_table::table::control_raw` triggered by safe API
- `2026-05-007` pulldown-cmark — `Option::unwrap()` on `None` in `parse.rs:2367` via crafted markdown input

---

## By API surface

All 6 findings are reachable via **safe public APIs** (`rkyv::from_bytes::<T>` or
`rkyv::access::<T>`). None require `unsafe` blocks in user code.

---

## By status

| Status | Count | Findings |
|---|---|---|
| PUBLIC-DISCLOSED, awaiting fix | 6 | 2026-05-001/002/003/005/006/008 |
| TRIAGE-FLAKY (held back) | 1 | `004 vec_hashmap_uaf` — non-deterministic reproduction, not published |

---

## Methodology timeline

- **2026-05-11**: First 5 deterministic findings discovered + writeups produced + private disclosure email to rkyv maintainer
- **2026-05-12**: rkyv `SECURITY.md` updated — AI-discovered findings skip embargo. Findings filed in public tracker. Autonomous rotator surfaced finding 008 (3 min from empty corpus, ML-prioritised harness); filed as rkyv#669.
- **2026-05-19**: pulldown-cmark finding 007 filed public — coordinated disclosure completed, fix in PR #1096.
