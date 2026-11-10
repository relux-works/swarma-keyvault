# Lab Namecoin wrapper for the existing local KeyVault profile

See [offline lab testing](../../docs/lab-testing.md) for exact pinned fixture builds and full-suite commands. Missing fixtures fail the suite.

A changed owner generation is persisted as refusal only after exact ASCII
name/outpoint and canonical confirmed transaction/header checks. This precedes
value decoding: Core's `value_error` or omitted value cannot hide a confirmed
replacement. Value and record errors still refuse strictly. An unrelated,
malformed, unconfirmed or unavailable generation claim is not canonical
replacement evidence. Retain the same private root across restart; a restored
original branch and newly signed request cannot reopen a persisted closure.

The original anchor is independently pinned, so its canonical displacement can
also be established when Core projects its transaction with zero confirmations
or its header with minus one. The wrapper reads the pinned header's height and
requires two equal, different canonical hashes at that height between matching
valid tip observations, a matching canonical block header and confirmation depth,
and the canonical hash at the observed tip height. Missing replies, inconsistent heights, changing hashes
or tips provide no displacement proof. These bounded sequential reads do not
form an atomic Core snapshot and cannot exclude an unobserved transition away
and back between calls.

Malformed values, unavailable requester history, failed second name reads and
unavailable or malformed tip replies refuse the attempt without persisting a
lifecycle claim. A healthy restoration with a fresh valid request can recover.
Confirmed replacements are rechecked with matching name identity, confirmed
canonical generation and stable tips before closure, including replacements
whose value cannot be decoded. The separate conservative unknown/spent seal
policy still persists refusal. Each new latch records its evidence reason;
old latch files retain their refusal meaning.

This is a lab observation library with default regtest compatibility and an
explicit independent mainnet policy. `Verifier.Verify` reads
public facts through an independently installed own-node `Node` read broker,
then invokes an unchanged `swarma-keyvault grants verify` executable using
closed argv. It returns a repeatable in-memory `Observation` with verdict
`verified-lab-observation`. This value carries no admission authority or
single-use reservation. The component is a verification observation adapter.
It never invokes `execute`, an issuer, a wallet, a
hardware provider, a network client or a watcher.

`Policy.Network` and `Policy.Genesis` are independent operator inputs. Omitting
both retains `regtest` and `RegtestGenesis`. Explicit regtest requires that
exact pair. Mainnet requires `main` and `MainnetGenesis` together; an omitted
field, unknown network or wrong network/genesis pair refuses. RPC chain claims,
names, certificates and requests never select the network policy. The current
RPC chain and block-zero hash must separately match it. The existing one-block
revocation rule remains laboratory policy on mainnet, not a finality guarantee.
The finite [own-node bridge](../../tools/labownnode/README.md) supplies a separate
read-only transport only after independent route installation and review.

The legacy Linux `labcompose INPUT` read broker owns private, pollable copies of its inherited
protocol pipes. Cancellation closes those copies and interrupts both request
writes and reply reads; it also bounds the final output write. A canceled pipe
is terminal: partial requests and late replies are never retried. Inherited
descriptors remain open with unchanged flags. Non-pollable protocol endpoints
are refused. The wrapper checks cancellation again after its final seal read
before returning an observation. The separate supervisor kill/reap bound remains
required.

The explicit `labcompose --owned-protocol INPUT` mode instead accepts exclusive
ownership of dedicated anonymous stdin/stdout pipe endpoints created by its
supervisor. It may change their flags and close them on cancellation. This
portable Unix route avoids `/proc`; do not use it for shared descriptors. The
new own-node supervisor creates and transfers those endpoints. `CLIHash` is
always independently supplied and is never replaced by the bridge. Input,
certificate and request files are bounded before reading into memory.

The default CLI's `grants verify` accepts `--config`, `--certificate`,
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

The local profile retains its existing wire format and repository target.
`Policy.ExpectedOwner` is required independently installed identity policy.
Its exact value becomes both enrollment `owner_mxid` and the verifier’s
`--owner-mxid` option. The verifier must support that option and remain pinned
by `CLIHash`. Supply the owner independently of the certificate, name record,
request or public key. The existing `labcompose` JSON `Policy` object carries
this field. The lab fixture signer likewise requires explicit `--owner-mxid`
when issuing a certificate. The reverse-direction fixture uses independently
installed pins, subject, audience, cycle, issuance and seal facts.

Here the labels describe simulated test actors:
Alexis-sim signs with an ephemeral software P-256 key; Ivan-agent-sim signs the
request using a distinct ephemeral software P-256 key. No real owner's key,
Matrix device authentication, encrypted delivery or generic platform grant is
implied. This is the existing local certificate/request format, not `grant/1`
on `swarm-envelope/2`, and cannot be substituted for that platform route.

The name record vocabulary below is a **lab proposal**, not a published or
approved owner record schema. Each complete value must fit 520 bytes.
The owner name carries `swarma.keyvault_owner_spki`,
`swarma.keyvault_certificate_sha256` (SHA-256 of the exact signed envelope bytes)
and `swarma.keyvault_seal` with exact `txid`/`vout`. The requester name carries
`swarma.keyvault_requester_spki`. The pin fields are exactly spelled, strict
canonical unpadded base64url of canonical P-256 SPKI DER. Unknown record fields
are preserved by not rewriting either record. Duplicate JSON members, aliases
that attempt to select a pin, malformed keys and expired names refuse.

This experiment supports Namecoin's byte-preserving ASCII route. Every
`name_show` call supplies a second argument exactly
`{"allowExpired":false,"nameEncoding":"ascii","valueEncoding":"ascii"}`.
Both response encoding fields must be present and equal `ascii`. The decoded
name and complete record value must contain only bytes `0x20` through `0x7f`,
matching the official ASCII validator. Encoding error fields refuse, even when
a value is also present. No text normalization or replacement is performed.
The node must also use ASCII name/value configuration for `getrawtransaction`
name operations; their complete `name_encoding` and `value_encoding` fields
are required and encoding errors refuse. Other node encoding configurations
are outside this lab interface and fail closed.

The interface is bound to [Namecoin Core source
`c68e6837b62065243ef6d1acac51446cc35047d2`](https://github.com/namecoin/namecoin-core/tree/c68e6837b62065243ef6d1acac51446cc35047d2):
`src/rpc/names.cpp` defines the `name_show` options and projections;
`src/names/encoding.cpp` defines byte-preserving ASCII validation and emits
encoding/error fields; `src/core_io.cpp` projects transaction name operations
using the configured encodings. Controls include the actual option argument,
complete encoding fields, missing/mismatched fields and encoding errors. This
source comparison does not qualify a running node or RPC transport.

The wrapper checks the independently selected network/genesis and node readiness, both current name
outputs and confirmed canonical blocks, the owner's exact name-committed
certificate hash and seal, exactly one `OP_RETURN 6a20<certificate hash>`, and
an issuer-address seal with `gettxout(txid,vout,true)`. Null/unknown seal reads
refuse, including mempool spends. It re-resolves both names, checks a stable
tip, and checks the seal again after KeyVault verification. Certificate owner,
requester hash, requester signature, subject, audience, certificate reference,
action, target, cycle and exclusive expiry are checked by the unchanged CLI.

A private `closed-<exact certificate hash>` refusal latch survives verifier
object/process restart when the same owner-private root is retained. An observed
confirmed owner issuance-generation replacement, spend, unknown seal, anchor
reorg, confirmed mid-observation name-generation change or valid changed tip
closes that certificate. A first-block spend is final for this lab policy;
restoring the UTXO after a reorg does not reopen it. The root must not be deleted
or recreated during a run. This is a small refusal latch, not a durable
multi-host lifecycle service. Persistence relies on successful local filesystem
writes/fsync; I/O failure still refuses the current instance. There is no
crash-consistency qualification or cross-process concurrency qualification.
Confirmed generation replacement is checked against canonical transaction
history before parsing the replacement record or resolving the requester.
Restoring the original public branch and constructing a fresh verifier with
the same retained root still refuses after successful latch persistence.

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

Repeated verification of the same request is intentional and does not consume
it. Verification at a later explicit timestamp can still succeed on an
unchanged tip; this component has no 30-minute no-block STOP timer. The
integrating admission layer must supply durable anti-replay across restarts,
trusted time and an independent watcher enforcing the exclusive 30-minute
no-block STOP. That integration needs its own whole-system review, including
duplicate requests/restarts and the timer boundary. No admission provider or
effect executor is supplied by this library.

Run the controls in a separate offline sandbox with read-only source/tooling,
private 0700 HOME/TMP/cache and no signing socket. For default controls, use a
CLI built from the pinned unchanged forward base:

```sh
LAB_KEYVAULT_CLI=/absolute/private/build/swarma-keyvault \
  go test ./lab/namecoinwrapper -skip TestMirror -count=1 -v
```

For reverse controls use the exact admitted configurable verifier, the exact
explicit-owner signer and the candidate `tools/labcompose` build, each as a
separate executable. Build them in the offline sandbox from the immutable
source graph supplied for review, then run:

```sh
LAB_KEYVAULT_CLI=/absolute/private/build/configurable-keyvault \
LAB_TEST_SIGNER=/absolute/private/build/labtestsigner \
LAB_COMPOSE=/absolute/private/build/labcompose \
LAB_OWN_NODE=/absolute/private/build/labownnode \
LAB_NODE_FIXTURE_CLI=/absolute/private/build/fake-node-cli \
  go test ./lab/namecoinwrapper ./lab/sealwatch -count=1 -v
```

Build the inert fake node CLI with
`go test -c -o /absolute/private/build/fake-node-cli ./lab/namecoinwrapper`
without `-race`; the parent suite can still run with `-race`. This avoids a
race-runtime exit sleep on every synthetic read subprocess and leaves all
production call/observation deadlines intact. The fake binary's TestMain only
serves bounded public test transcripts for the fixed CLI invocation.

Default controls call the actual existing `local-prepare` with separate DER
files, use the test-only in-process low-S signer, and call actual `grants verify`
through the wrapper. Reverse controls additionally require `LAB_TEST_SIGNER`
pointing to the separately built explicit-owner lab signer. They serialize only
freshly generated synthetic keys in private temporary custody, invoke its actual
certificate and request modes, and remove custody with the fixture. The two
signing roles share one test UID and process; this is not a security boundary
against same-UID actors or proof of cross-host custody. Public node replies are
inert stubs, not live freshness evidence. Positive observation,
negative causal controls, exact byte boundaries and restart refusal are covered.
The unchanged seal watcher consumes that same reverse certificate digest and
seal in causal UNSPENT, mempool SUSPEND and first-block FINALREVOKED controls.
Restoring the old transcript and signing a fresh request cannot reopen the
wrapper's successfully persisted refusal latch. This does not qualify crash
consistency, protected time or a real 30-minute idle STOP.
The package has no release signer, production Enclave fallback, BIP47 contact
or four-actor orchestration. These reverse source controls are not a new
regtest, native qualification or admission. Fresh independent WHOLE review of
both exact source graphs and an exact-source Meta marker are required before
any composition claim or live use; component acceptance does not supply them.
