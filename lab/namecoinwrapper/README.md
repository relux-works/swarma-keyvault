# Lab Namecoin wrapper for the existing local KeyVault profile

This is an offline/regtest-only library experiment. `Verifier.Verify` reads
public facts through an independently installed own-node `Node` read broker,
then invokes an unchanged `swarma-keyvault grants verify` executable using
closed argv. The only admission effect is an in-memory `Admission` value.
It cannot run on mainnet and never invokes `execute`, an issuer, a wallet, a
hardware provider, a network client or a watcher.

The pinned existing CLI's `grants verify` accepts `--config`, `--certificate`,
`--request` and the explicit test observation `--at`. It does **not** accept
owner/requester SPKI file flags. The documented `grants-local-enrollment-2`
configuration is the adapter: independently installed subject/audience/cycle
policy plus the two freshly resolved public name pins become a temporary
canonical owner-private 0600 configuration. Certificate/request files are
bounded private copies; all temporary observation files are removed on return.
There is no existing enrollment lookup or fallback. Replacing an execution
configuration would change its journal epoch; this wrapper only verifies and
never opens execution state.

Policy also pins the issuance transaction/block and seal outpoint for the exact
lab run, as existing chain-lab fixtures do. A later current name update or seal
replacement cannot silently revive the same certificate. Pin those public
anchor facts independently when admitting the run, never from request fields.
Use an ASCII private root: the existing KeyVault configuration grammar rejects
non-ASCII string bytes rather than repairing or normalizing them.

The local profile retains its existing wire labels, including the fixed owner
identifier and repository target. Here they describe simulated test actors:
Alexis-sim signs with an ephemeral software P-256 key; Ivan-agent-sim signs the
request using a distinct ephemeral software P-256 key. No real owner's key,
Matrix device authentication, encrypted delivery or generic platform grant is
implied. This is the existing local certificate/request format, not `grant/1`
on `swarm-envelope/2`, and cannot be substituted for that platform route.

The name record vocabulary below is a **lab proposal**, not a published or
approved owner record schema. Each complete UTF-8 value must fit 520 bytes.
The owner name carries `swarma.keyvault_owner_spki`,
`swarma.keyvault_certificate_sha256` (SHA-256 of the exact signed envelope bytes)
and `swarma.keyvault_seal` with exact `txid`/`vout`. The requester name carries
`swarma.keyvault_requester_spki`. The pin fields are exactly spelled, strict
canonical unpadded base64url of canonical P-256 SPKI DER. Unknown record fields
are preserved by not rewriting either record. Duplicate JSON members, aliases
that attempt to select a pin, malformed keys and expired names refuse.

The wrapper checks regtest genesis and node readiness, both current name
outputs and confirmed canonical blocks, the owner's exact name-committed
certificate hash and seal, exactly one `OP_RETURN 6a20<certificate hash>`, and
an issuer-address seal with `gettxout(txid,vout,true)`. Null/unknown seal reads
refuse, including mempool spends. It re-resolves both names, checks a stable
tip, and checks the seal again after KeyVault verification. Certificate owner,
requester hash, requester signature, subject, audience, certificate reference,
action, target, cycle and exclusive expiry are checked by the unchanged CLI.

A private `closed-<exact certificate hash>` refusal latch survives verifier
object/process restart when the same owner-private root is retained. An observed
spend, unknown seal, anchor reorg, mid-observation name change or changed tip
closes that certificate. A first-block spend is final for this lab policy;
restoring the UTXO after a reorg does not reopen it. The root must not be deleted
or recreated during a run. This is a small refusal latch, not a durable
multi-host lifecycle service. Persistence relies on successful local filesystem
writes/fsync; I/O failure still refuses the current instance. There is no
crash-consistency qualification or cross-process concurrency qualification.

`Node.Call` must honor context cancellation and return fresh own-node replies,
never cached successes on transport or health failure. The wrapper bounds name
replies to 4096 bytes, other public replies to 65536 bytes, JSON depth to 24,
transaction outputs to 128, certificate/request to existing 98304/12288 bytes,
CLI stdout/stderr to 8192 bytes each, and an observation context to 10 seconds.
The independently installed CLI SHA-256 is checked before invocation. The node
and executable policy are trusted local capabilities; a caller-supplied JSON
snapshot is never a live freshness proof. An isolated or lagging node cannot
be diagnosed solely from internally consistent RPC replies. Consequently this
prototype does not qualify live stale-node detection, protected time, atomic
chain/effect admission, durable replay prevention or revocation between calls.
Use of the explicit test observation must never become a production clock.

Run the controls in a separate offline sandbox with read-only source/tooling,
private 0700 HOME/TMP/cache, no signing socket and a CLI built from the pinned
unchanged base:

```sh
LAB_KEYVAULT_CLI=/absolute/private/build/swarma-keyvault \
  go test ./lab/namecoinwrapper -count=1 -v
```

Tests call the actual existing `local-prepare` with separate DER files, use
only the test-only in-process low-S signer, and call actual `grants verify`
through the wrapper. The test keys are never serialized. Positive admission,
negative causal controls, exact byte boundaries and restart refusal are covered.
The package has no release signer, production Enclave fallback, BIP47 contact,
mirror direction or four-actor orchestration. Fresh independent review and an
exact-source Meta marker are required before any live composition.
