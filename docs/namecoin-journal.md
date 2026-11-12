# Namecoin journal and result persistence

The internal Go components prepare public transaction validation and journal
persistence. They are not yet connected to a public signing command or qualified
native custody flow. A passing portable test does not establish Keychain access,
biometric consent, code identity or actual private-operation ordering.

`internal/namecoinjournal` separates public physical records from the confined
integrity anchor. The anchor's key and token belong only in the qualified
protected Keychain item and same-process owned buffers. They never enter the
journal, descriptor, result cache or public receipt. Account correspondence must
be rederived after fresh native unseal before authenticated reconciliation.

## Physical files

`CreateStorage` is a create-only operation for explicit initialization;
`LoadStorage` never creates missing state. Both independently acquire the fixed
process-owned kernel gate before reading journal state. Keep the handle until
all private material is cleared and all protected readbacks are complete.

The root is the actual OS user's home, resolved by numeric uid, followed by
`Library/Application Support/mac-keyvault/namecoin-journal/v1/<locator>`.
`HOME` and request paths do not select it. The locator is the existing hash of
the two length-prefixed public purpose identities.

The home and existing Library directories require the actual user's ownership,
owner read/write/search, no group/other write and no special mode bits. Dedicated
directories require exactly0700. Every file requires ownership by that user,
regular-file type, exactly0600 and a single link. Directory/file access uses
held descriptors, no-follow operations and close-on-exec. Named entries must
still identify the held inode before and after an operation. There is no chmod,
unlink, rename, overwrite or automatic repair route.

| File | Contents | Bound |
| --- | --- | --- |
| `sidecar` | Exact public selected-pair binding | 640 bytes |
| `records` | `KVJF1` plus zero byte, then u32BE length and complete frame per record | 64 MiB,65536 records |
| `attempt-<idhex>` | Exact public request/independent-selection descriptor | 12 MiB |
| `result-<idhex>` | Exact complete public result, including any final newline | 8 MiB |

Frames retain the `KVNF1` representation and sequential hash linkage. The bound
dispatch body uses `KVNT2`: a DISPATCHED tag, attempt ID, descriptor commitment
and outpoints. Other transition bodies retain `KVNT1`. The descriptor commitment
binds the actual immutable plan, phase, slot and independently selected facts;
its hash is not an authentication key.

All writes check state, write complete bytes, fsync and read back exact bytes.
Create-only files also fsync their directory. A partial write remains evidence;
the loader refuses rather than truncates or completes it. A detected filesystem
failure disables further writes through that handle, even if another actor
later repairs the files. No availability or rollback resistance against a
hostile OS or root is claimed.

## Protected completion

The required lifecycle is durable DISPATCHED plus protected update/readback
before ECDSA, then independently verified complete result/cache/output and
durable SIGNED plus protected update/readback before acknowledgement. The file
API implements only public persistence; actual native private-effect ordering
and explicit output descriptor integration remain separate work.

A result receipt references its own DISPATCHED sequence and frame hash. The
immediately following SIGNED frame commits SHA256 of the exact complete result.
This avoids putting the final SIGNED head inside the result it hashes.
`Anchor.VerifyCompleted` requires account correspondence, complete checked
history, exact bound attempt/descriptor, the referenced DISPATCHED and matching
subsequent SIGNED/result. Later legitimate history may advance the current
anchor; historical membership, rather than equality to that current head,
establishes the reference.

A result file alone, unfinished dispatch, UNKNOWN, different attempt or result,
wrong reference, nonadjacent completion or a self-consistent substituted
integrity key refuses. Reconciliation performs no new ECDSA, initialization,
promotion of partial state or replay-fence release. This is not Keychain CAS,
hardware monotonic storage or a network exactly-once guarantee.

## Focused tests

Use the repository's confined macOS route:

```sh
MAC_KEYVAULT_SKIP_KEYCHAIN=1 KEYVAULT_CODESIGN_TESTS=0 scripts/keyvault-test-confined.sh -work -p 1 -parallel 1 -race -count=1 -timeout=120s -v ./internal/namecoinwire ./internal/namecoinpsbt ./internal/namecoinjournal
```

Retain the emitted work directory and redirect logs under `.temp/`. Tests use
public fixture account material and disposable files only. They exercise actual
file permissions, symlink/hardlink/FIFO/entry-replacement refusals, the kernel
gate, persistence/reopen, typed replay and protected-completion checks. Native
Keychain, code identity, real biometry and installed adoption remain unqualified
by these tests.
