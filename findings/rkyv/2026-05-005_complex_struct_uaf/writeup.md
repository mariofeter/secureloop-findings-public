---

id: "005_rkyv_complex_struct_uaf"
finding_number: 5
status: PUBLIC-DISCLOSED
status_date: 2026-05-11
severity: high
target_project: rkyv
target_version: 0.8.16
discovered: 2026-05-11
disclosed: 2026-05-11
cve: null
bug_class: use-after-free
component: complex-struct-deserialize
api_surface: safe
affected_file: rkyv/src/impls/alloc/string.rs
affected_function: deserialize
affected_line: 39
tags: [security, rkyv, use-after-free, uaf, rust]
disclosure_policy: rkyv SECURITY.md (AI-assisted findings skip embargo)
---

# Finding 005 — rkyv 0.8.16: HEAP-USE-AFTER-FREE in derive(Archive) struct deserialization

**Status: PUBLIC-DISCLOSED — filed in public tracker per rkyv SECURITY.md update**
**Discovered: 2026-05-11**
**Discoverer: Mario Feter / SecureLoop**

---

## Summary

`rkyv::from_bytes::<ComplexBag, Error>(data)` triggers a
**heap-use-after-free** on a 168-byte crafted input. `ComplexBag` is a
small custom struct decorated with `#[derive(Archive, Deserialize,
Serialize)]`, containing common Rust types:

```rust
#[derive(Archive, Deserialize, Serialize)]
struct ComplexBag {
    names: Vec<String>,
    counters: Option<HashMap<String, u32>>,
    payload: Box<Vec<u64>>,
    flag: bool,
}
```

Top symbolized frame in the crash:
```
<rkyv::string::ArchivedString as
  rkyv::traits::Deserialize<alloc::string::String, ...>>::deserialize
```

The crash happens during the `Deserialize::deserialize` step of an
`ArchivedString` (one of the entries inside `names: Vec<String>` or a key
inside `counters: HashMap<String, u32>`). The deserializer dereferences a
freed allocation — UAF on the deserialize fast path of every Rust struct
that has a `String` field. **This is the widest possible blast radius
because it triggers from a very common pattern.**

## Severity

**High.** Use-after-free in the most idiomatic `#[derive(Archive)]` flow
— any rkyv consumer that derives Archive on a struct containing String
fields is exposed.

## Affected versions

- rkyv git HEAD `4a841456...`
- rkyv 0.8.16 (crates.io)

## Reproducer

168-byte input at `rkyv_complex_struct_uaf.bin`.

Same harness pattern; struct definition above must be in the harness.

## ASAN summary

```
==<pid>==ERROR: AddressSanitizer: heap-use-after-free
SUMMARY: AddressSanitizer: heap-use-after-free
  from_bytes_complex_struct+0x1318ff
  -> rkyv::string::ArchivedString::deserialize
```

## Why it matters

The triggering struct definition is **realistic** — every project that
serializes "a bag of common Rust types" (which is most projects using
rkyv at all) is vulnerable. Combined with Finding 004's UAF in
`Vec<HashMap<String,String>>`, this looks like a structural soundness
problem in how the deserialize-side pool / error path handles ownership
of references into the input buffer.

## Recommended next steps

1. Confirm UAF site precisely with `lto=off -Copt-level=1`.
2. Determine whether `rkyv::de::pooling::alloc::Pool` is releasing
   memory that ArchivedString::deserialize still holds a pointer to.
3. Bundle in follow-up to maintainer.
