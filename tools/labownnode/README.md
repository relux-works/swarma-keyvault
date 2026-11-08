# Finite own-node observation bridge

`labownnode` supervises the existing `labcompose` JSON read pipe and invokes an
independently installed Namecoin Core CLI for each closed read method. It uses
no shell, URL, remote command, wallet method, signing method or write method.
The CLI's own configuration/authentication stays with its operator. This source
does not supply, discover or qualify a real endpoint or credential route.

Build `tools/labownnode` and `tools/labcompose` from the same reviewed candidate
tree with the committed toolchain and dependency checksums. The cryptographic
`swarma-keyvault grants verify` executable remains a separate immutable input;
its existing independent owner-policy interface must be present. Do not replace
that source pin with the candidate's default CLI or recompute its policy hash
from an executable at observation time.

The supervisor supports Unix dedicated anonymous pipes on Linux and macOS. It
starts `labcompose --owned-protocol INPUT`, transfers the child pipe endpoints
exclusively, and closes its copies. The child may set nonblocking flags and
close those transferred endpoints on cancellation. This route requires no
`/proc`, GNU `timeout`, shell scripts or Python. The legacy `labcompose INPUT`
mode retains its Linux `/proc` reopening and inherited-descriptor contract.
Cross-compilation does not qualify native macOS behavior or a running node.

Before creating children or protocol endpoints, trusted startup marks every
descriptor above stderr close-on-exec. Linux requires atomic `close_range`
with `CLOSE_RANGE_CLOEXEC` and refuses if unavailable. Darwin enumerates its
own `/dev/fd` view and checks/sets `FD_CLOEXEC`; enumeration or fcntl errors
refuse, except descriptors that have already closed. Enumeration does not use
the current descriptor limit, so inherited handles above a lowered limit are
included. Nothing closes Go runtime handles. Only deliberate standard streams
and the subsequently created owned protocol endpoints cross child boundaries.
Runtime concurrent opens already use close-on-exec; concurrent non-CLOEXEC
openers or untrusted native code are outside this trusted startup contract.
This is descriptor custody for trusted non-detaching children, not an
arbitrary-child sandbox. Executable and parent-path immutability is still
required; hashing then executing a path does not close replacement races.

Install a private route JSON matching [route.schema.json](route.schema.json).
All fields are mandatory, exactly spelled, unique string members. `Network`
and `Genesis` must be an admitted pair: `main` with
`000000000062b72c5e2ceb45fbc8587e807c155b0da735e6483dfba2f0a9c770`,
or `regtest` with
`0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206`.
There is no route default. The wrapper's omission of both policy fields still
means regtest; it can never follow a mainnet RPC claim automatically.

The operator supplies the exact absolute `NodeCLI`, its `NodeCLISHA256`,
`NodeConfig`, `NodeDataDir`, candidate `Compose` and `ComposeSHA256`, and a
retained private mode-0700 `PrivateRoot`. Executables and configuration must
remain immutable during a run, including parent directories. `RouteID` names
the separately admitted own-node route; the string alone confers no trust.
The route admission must establish the actual fully validating own node,
endpoint and existing authentication, ASCII name/value projection, transaction
lookup availability and operator custody. A consistent RPC transcript alone
cannot establish freshness or detect isolation. Do not put credentials in this
JSON or pass credential flags. The bridge does not read node configuration
contents and does not export configuration, diagnostics or node replies.

The exact CLI invocation for every call is:

```text
NodeCLI -conf=NodeConfig -datadir=NodeDataDir -chain=Network -rpcclienttimeout=2 METHOD PARAM...
```

`METHOD` is one of `getblockchaininfo`, `getblockhash`, `getblockheader`,
`name_show`, `getrawtransaction`, `gettxout`, `getrawmempool`, `getblock`.
The existing pipe supplies at most three bounded JSON positional parameters.
Strings become bare CLI positional strings; other JSON values retain their
JSON encoding. Option-shaped string parameters refuse. There are no additional
operator-provided arguments. An actual CLI lacking these options/projections
refuses and needs a separately reviewed route definition, never guessed flags.
Core prints `getblockhash` results as bare text; the bridge requires an exact
lowercase 32-byte hash (with at most the final CLI LF) and wraps it as a JSON
string for the pipe. Other methods require JSON output. Arbitrary text and
diagnostics are never interpreted as successful JSON results.
The sole exception is successful empty stdout from `gettxout`, Core's null
result representation; it becomes JSON `null`, preserving spent-seal refusal.

Install a separate `labcompose` observation input. The verification input
schema is [input.schema.json](input.schema.json). Its `Mode` is `verify` or
`watch`; `Policy.Network`/`Policy.Genesis` must agree with the route. Watch mode
also requires matching `Binding.Chain`/`Binding.Genesis`. For verify mode the
input contains `Policy`, absolute `Certificate` and `Request` paths, and an
explicit RFC3339 `At` lab instant. Policy retains independently supplied:

- `ExpectedOwner`, exact `OwnerName` and `RequesterName`;
- `Account`, `Device`, `Deployment`, `Executor`, `Cycle`;
- separate verifier `CLI` and independently installed `CLIHash`;
- retained mode-0700 `PrivateRoot` for the same persisted refusal latch;
- original `AnchorTxID`, `AnchorBlock`, `SealTxID`, `SealVout`.

Names select neither owner identity nor network. The owner's complete ASCII
name value must carry the exact certificate-envelope hash and original seal,
in addition to the complete SPKI. Its issuance transaction must include exactly
one full certificate-hash OP_RETURN. Existing SPKI-only registration receipts
do not supply those issuance facts. Never delete the retained refusal root to
recover from a spend, reorg, changed issuance or new signed request.

After independent whole-graph review, the exact-source marker and actual route
admission, the operator command is the following. These variables must name
the installed reviewed binary and independently supplied absolute JSON files;
no live route file or certificate is provided by this source change.

```sh
"${LABOWNNODE_BIN:?supply reviewed absolute executable}" \
  "${ROUTE_JSON:?supply admitted absolute route JSON}" \
  "${OBSERVATION_JSON:?supply independent absolute observation JSON}"
```

Exit 2 means startup, route, transport or bound refusal; exit 124 is the
independent eighteen-second process lifetime cutoff. Exit 0 means the child
returned a receipt, which can still contain `result.verified=false` or a watcher
refusal state. Always inspect that result. The receipt schema is
[receipt.schema.json](receipt.schema.json); it binds network/genesis, input and
executable hashes, timestamps and read count. `effect_authorized` and
`node_route_qualified` are always false. A verified observation authorizes no
execution, broadcast, repository action or admission.

Bounds are 16 KiB route, 64 KiB observation input, 64 MiB executable hashing,
256 read calls, 8 MiB per transport reply/pipe line, 64 MiB aggregate protocol
and reply data, two seconds per node call, fifteen seconds for the composition,
one second subprocess pipe-reap grace, eighteen seconds total CLI lifetime
including startup and the final receipt sink, and 8 KiB captured diagnostics per child.
The wrapper's tighter 10-second, reply, certificate, request and CLI-output
bounds still apply. All child diagnostics are withheld. The bridge
reaps direct subprocesses; trusted pinned executables must not detach children.

The existing first-block revocation decision is an explicit laboratory policy
on mainnet too, not a consensus finality guarantee. Mempool spend/unknown seal
refuses the wrapper; successful latch persistence prevents reopening after
restoration or a fresh valid request. T1 MVP treats unknown mempool data as
nonblocking and requires exact-block success in its separate receipt route;
that rule does not weaken this wrapper's seal checks. Authenticated own-node
mempool serving for T1b remains separate. Experimental key custody, public
funding/name prevouts and the UTXO ledger remain external inputs. Existing
spend caps and per-raw-hex authorization remain with the operator and do not
follow from source preparation.
