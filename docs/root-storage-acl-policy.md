# Root storage ACL policy

The root-grants vault stores a sealed item in the login keychain through the legacy
file-keychain ACL APIs. Before it adds that item, and every time it reads one back,
it asks one predicate whether the item's owner and ACL set are exactly a form that
was observed on a real system. This document states that predicate, the evidence it
comes from, and its limits. The code is `internal/rootqualification/policy.go`; the
wiring is `internal/keyvault/root_grants_vault.go`.

## What is admitted

A **positive allowlist**: only the two forms below are admitted. Nothing is learned
at run time, a form that was not observed is refused, and a successful add, a
matching readback or a refused foreign read does not admit anything by itself.

The access object that the vault builds in memory (the **intended** form) and the
item that the Keychain stores (the **stored** form) are not the same ACL set: the
Keychain adds an Integrity ACL and a second, identical partition ACL and lists the
ACLs in another order. They are therefore admitted through two entry points,
`AdmitIntended` (before the add, and in the check made before any recovery word is
requested) and `AdmitStored` (after the add and in the public lookup), each against
its own form. There is no union form: the intended projection is refused by the
stored entry point and the reverse.

Both forms have the owner row uid 0, gid 0, type 0. ACLs are compared as a multiset,
so their order does not matter. Every ACL has readable names, readable contents, a
present description, prompt bits 0 and a readable raw prompt of version 257, flags 0.

| ACL | Authorizations (numbers) | Applications | Description | Intended | Stored |
| --- | --- | --- | --- | :---: | :---: |
| encrypt | `ACLAuthorizationEncrypt` (35) | not restricted (NULL list) | the item descriptor | 1 | 1 |
| change | `ACLAuthorizationChangeACL` (65536) | explicitly empty list | the item descriptor | 1 | 1 |
| release | Decrypt, Derive, ExportClear, ExportWrapped, MAC, Sign (24, 28, 37, 38, 59, 115) | exactly one: the owning vault's designated requirement, as compiled bytes and as text | the item descriptor | 1 | 1 |
| partition | `ACLAuthorizationPartitionID` (65538) | NULL list | the hex encoding of the property list whose only string is `teamid:262RZ595FP` | 1 | 2 |
| integrity | `ACLAuthorizationIntegrity` (65539) | NULL list | 64 lowercase hex characters | 0 | 1 |

The item descriptor is the description of the access object: `Root grants key` for a
root item (`KVRGAccessDescriptor` in `internal/keyvault/root_grants_store_darwin.c`,
compared by a test with the Go constant) and `Root ACL public qualification` for the
public-marker item of the qualification lane. One predicate, two instances. Anything
else is refused for a named reason: the owner row, an authorization set that is not
listed, unreadable names, contents or prompt, another description, another
application list, another requirement (the helper, a second application, a widened or
truncated requirement, a missing or unreadable one), or another number of an ACL.

## Evidence

The forms were recorded by the attended public-marker qualification of the signed
build at source head `c2a03e7f9797ef0d4e817fc7f4a6fb44461f55d1` on macOS 26.5.1
(arm64), on 2026-11-13: the item was created, read back, refused to the foreign
executable and refused to the helper. The two public projections are the fixture
`internal/rootqualification/testdata/observed/h4-frames.json`:

| Frame | Bytes | SHA-256 |
| --- | ---: | --- |
| intended (before the add) | 1437 | `0885f13cdf52426c4bfeb0d49d8d9e4cb268c2f0267a14a0cbb55c38e4af46c2` |
| stored (read back) | 2199 | `53e6776f24208d795cc07c39355f4ab0a245cddfdddece7b784a9c1c9720d31a` |

A test re-encodes both and requires those digests, so a hand-edited fixture cannot
stand in for an observation. An in-process native test (`-tags kvqfault`, no Keychain
item) builds the intended object with the marker and with the production descriptor
and compares each with the table. The vault requirement is checked against the
signing policy, and the team partition against the team of that policy.

## Limits

- The stored form of an item created with the **production** descriptor has not been
  observed; it is the marker's stored form with the descriptor substituted. It is
  confirmed by creating a real production item (a rehearsal against a disposable
  pair), not by this document.
- One item on one machine on one operating-system version was observed. Whether the
  Integrity description differs per item is not known, which is why it is admitted by
  pattern rather than by value.
- Another macOS version may emit other forms. The predicate then refuses, which blocks
  root storage until new evidence extends the table and the change is reviewed. It is
  never loosened to make an add pass.
- The encrypt ACL carries no application restriction in the observed object. Whether
  that is acceptable for this item is a review question, not something the
  observation settles; the release ACL, which carries every authorization that reads
  or uses the item, is restricted to the owning vault.
- The predicate reads ACLs only. The item's service, account, value and metadata are
  checked by the attach flow.

## Extending the table

Observe the new form on the affected system with the attended qualification, add the
public projections as a new fixture with their recorded digests, extend the table and
its forbidden-form tests together, and review the change independently. A form that
the tests do not list as admitted must stay refused.
