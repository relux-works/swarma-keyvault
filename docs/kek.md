# Service KEKs: `mac-keyvault-kek` (contract kek-1)

`mac-keyvault-kek` keeps a service's 32-byte key-encryption key (KEK) wrapped
to a non-extractable P-256 key in the login Keychain. At start, the service
gets the KEK back from the broker. The broker answers only the code the
wrapped envelope is bound to. The private key never leaves Security.framework.

The broker is a separate binary from `mac-keyvault`:
- Its keys' ACLs trust only the broker.
- Building or installing it touches no existing Keychain item.
- `mac-keyvault` is not rebuilt for it.

The keys are ordinary keyvault records: kind `key`, address `SERVICE/PURPOSE`, usage `decrypt`, label
`works.relux.mac-keyvault.key.<service>.<purpose>.v<N>`.

## Pieces

| Piece | What it does |
| --- | --- |
| `mac-keyvault-kek create --address S/P [--title T] [--not-after RFC3339]` | Creates generation 1 and prints address, generation, label, fingerprint and SPKI (base64 DER). The operator posts the fingerprint; the service pins it. |
| `mac-keyvault-kek pub --address S/P [--version N]` | Prints the same for an existing generation. |
| `mac-keyvault-kek unwrap --address S/P --socket PATH` | Serves one request on a new socket, then exits. A service runs it through `kekclient.Unwrap`, never by hand. |
| `mac-keyvault-kek rebind --address S/P --socket PATH` | Serves one rebind request (below), then exits. |
| `mac-keyvault-kek audit-verify` | Checks the audit log's chain under the same framing `unwrap` requires (one complete line per entry, ending in a newline, a private regular file), and prints the entry count and the chain head. |
| `pkg/kekclient` | Go client: `Wrap` (pure Go, public key only), `Preflight` (metadata-only option validation), `Unwrap`, `Rebind`, `ParseEnvelope`, the requirement allowlist, the error codes. |

Every command disables Keychain UI first. A call that would need a dialog fails instead.

## Envelope

The service keeps one envelope file, 0600 in its private data directory.

The clear part is one JSON object:
- `format` `mac-keyvault-kek-envelope`, `v` 1;
- `address`, `generation`, `fingerprint` (base64url SHA-256 of the key's DER SPKI);
- `kcv`, the key check value: HMAC-SHA256(kek, `"mac-keyvault-kek kcv 1"`);
- `ecies`, the sealed payload. It uses Security.framework's `kSecKeyAlgorithmECIESEncryptionCofactorVariableIVX963SHA256AESGCM`: an ephemeral P-256 point, the X9.63 SHA-256 KDF with the point as shared info, AES-GCM with a 16-byte IV, then point || ciphertext || tag.

The sealed payload repeats `address`, `generation`, `fingerprint` and `kcv`, and adds:
- `requirement`: the binding;
- `install_path`: where the bound service is installed;
- `kek`.

Both sides parse every contract object strictly, including nested `result`, `error` and `envelope` objects:
- exact member names, so no case aliases;
- no unknown, missing, repeated or null members;
- each member of its declared JSON type;
- exactly one object and nothing after it.

Any difference between the clear and the sealed header is refused. A KEK that does not match its `kcv` is refused as well.

Every shape, nested ones included, is checked before anything is decoded, so a refused answer never has a KEK decoded. Checking copies nothing: member values are views into the received bytes, which are cleared after use. A KEK is written only with `MarshalWithSecret`, straight into a buffer that is cleared after use, never through `json.Marshal`'s pooled encoder. This covers the buffers the client and broker own; copies inside the Go runtime, the crypto code or the kernel are outside its reach.

The binding is inside the ciphertext, so a same-user process cannot change it without breaking GCM. It also cannot make an envelope holding the service's KEK without knowing that KEK.

**Admitted requirement forms:**

- `cdhash H"<40 lowercase hex>"`, constructed by `RequirementForCDHash`;
- `certificate leaf = H"<40 lowercase hex>" and identifier "<identifier>"`,
  constructed by `RequirementForCertificate(identifier, certificateSHA1)`.

The certificate pin is SHA-1 of the complete leaf-certificate DER, as in Apple's
code-requirement language, and the identifier is the exact signed identifier.
It is not a subject name, Team ID, filename or chain anchor. The constructor
accepts uppercase fingerprint input and emits lowercase; serialized forms are
lowercase only. Identifiers are case-sensitive ASCII, 1–255 bytes: first
`[A-Za-z0-9]`, remaining `[A-Za-z0-9._-]`. No wildcard, escaping, alternative
spacing or additional requirement clause is admitted. `RequirementCertificate`
returns both fields only for the canonical certificate form;
`RequirementCDHash` returns false for that mode. No operational certificate is
a library default.

Wire framing and envelope version remain `kek-1`/1. New readers preserve legacy
CDHash envelopes. Older readers refuse certificate payloads and publish no KEK;
qualify and deploy the supporting client and broker pair before provisioning
that mode. A certificate binding is an explicit provisioning choice.

## Unwrap

Call `kekclient.Preflight(Options{Broker, SocketDir})` before changing provisioning state. It validates the same options as an exchange without drawing a nonce or creating a file, socket or process. `SocketDir` must already be a clean absolute path to a real directory owned by the current user, with no group or other permissions; a selected-directory symlink is refused. An existing private service data directory is supported. The generated `kek-<16 hex digits>.sock` pathname must fit the macOS broker's 103-byte limit, measured in UTF-8 bytes. An ordinary parent directory can therefore be at most 77 bytes; 72-byte and 77-byte parents produce 98-byte and 103-byte socket paths, while 78-byte and 81-byte parents are refused. No directory is created, relocated or repaired.

A budget refusal satisfies `errors.Is(err, kekclient.ErrSocketPathTooLong)` and its message contains no private path. Other option errors may contain paths: a service should map them to controlled failure classes rather than print raw errors or broker stderr. Preflight is a metadata observation, not a filesystem lock or proof of caller admission. The exchange repeats the same validation before preparing its nonce, cleanup or broker child; the broker retains its independent checks.

`kekclient.Unwrap(ctx, Options{Broker, SocketDir}, envelope)` takes these steps:
1. It runs the shared `Preflight` before preparing or starting the broker.
2. It starts the broker with a fresh socket path and waits for `listening PATH`.
3. It connects, sends one request line and reads one answer line.
4. It accepts the answer only if all of these hold:
   - the answer is a contract object about the same address, generation and fingerprint;
   - the KEK is 32 bytes;
   - the KEK matches the envelope's `kcv`.

   So a substituted broker cannot hand the service a KEK of its own choosing for an unchanged envelope.

   The clear `kcv` is not authenticated. A same-user process that can both rewrite the envelope file and replace the broker can pair a chosen KEK with its own `kcv`, and `Unwrap` returns that KEK. It is not the service's real KEK, and the original KEK is not disclosed. The service's own store check (an authenticated store header) must then refuse it and stop the service. At first provisioning there is no store yet; that step happens only in a recorded window, wrapped to the posted fingerprint.

The broker runs these gates, in order:
1. **The peer's code**, from the socket's audit token (`LOCAL_PEERTOKEN`, SecCodeCopyGuestWithAttributes). It must be validly signed, with hardened runtime and library validation, and without `com.apple.security.get-task-allow`. Otherwise a same-user process could inject into it and act through it.
2. **The request:** contract `kek-1`, the operation and address this process serves, a valid envelope.
3. **The key, through keyvault's own policy:** a readable valid record, usage `decrypt`, `not_after` not passed.
4. **Decryption with the Keychain key.** Then the payload must match the clear header and the key's fingerprint.
5. **The binding:** re-identify the same audit-token peer after decryption,
   recheck all hardening gates and require unchanged observed code facts. Then
   require the bound CDHash, or both the bound leaf certificate and signed
   identifier. Ad-hoc signatures have no leaf certificate and cannot satisfy
   certificate mode. Native validation disables online revocation/notarization
   access before signing metadata is read. The calls are synchronous and do
   not promise hard cancellation or measured absence of all network traffic.
6. **The audit log.** The entry is written and synced before the answer is sent. If the log cannot be written, nothing is answered.

Pipes and inherited descriptors are not a transport: a same-user parent can keep a copy of a pipe across exec.

`Unwrap` runs the broker in its own process group and kills that group once per exchange, before it reaps the broker:
- after a protocol error or at the deadline, at once;
- after a correct answer, once the broker has exited by itself, or after one second. A broker that does not exit in that time is killed, and its answer is refused.

The broker's pid, which is also the group id, cannot be reused before it is reaped, so the signal reaches only the broker's own group. No signal is sent from another goroutine. Cancelling the caller's context ends the exchange at once, even after the request was sent: it closes only the connection, and no KEK is returned. Pipes a descendant still holds are given up after two seconds. A process that leaves the group on purpose is not contained.

### Error codes (closed set)

| Code | Meaning |
| --- | --- |
| `bad_request` | Malformed request, another contract, operation or address, an invalid envelope |
| `caller_refused` | The peer is not the bound code, or its code could be injected into |
| `envelope_invalid` | Tampered, truncated or foreign envelope; header mismatch; another key's fingerprint |
| `not_found` | No such key generation |
| `expired` | The record's `validity.not_after` has passed |
| `usage_refused` | The record lacks usage `decrypt` |
| `metadata_unknown` | The record is unreadable or invalid |
| `rebind_refused` | Rebind target missing, not hardened, or already bound |
| `unsupported_primitive` | The record's primitive cannot decrypt |
| `security` | Security.framework or audit failure |

A client treats any other code, or any answer that is not a contract object, as `ErrProtocol`.

## Rebind

A service reinstall changes its cdhash. The bound service (still the old binary) calls `kekclient.Rebind`. The broker then:
1. checks the caller as for unwrap;
2. reads the code at the envelope's `install_path` itself; it must be a regular file, validly signed with hardened runtime and library validation, without get-task-allow, and not the code already bound;
3. re-seals the same KEK under `cdhash H"<that file's cdhash>"`.

The new envelope comes back; the KEK never does. The audit log records the new binding.

Successive builds signed with the same pinned leaf certificate and identifier
already satisfy a certificate binding. `Rebind` returns `rebind_refused` without
an envelope or KEK, including for a matching installed build. A different
certificate, identifier or invalid target also refuses. Rebind never changes
pins or converts binding mode. Certificate rotation or a mode change needs an
explicit service provisioning procedure.

## Service-side requirements

- Sign with `codesign --options runtime,library` and no get-task-allow.
- Have no command, flag or environment switch that prints, exports or re-wraps the KEK, or writes decrypted store contents to a path the caller chooses. A same-user process can run a byte-identical copy of the bound binary with its own arguments, and the broker answers it. Test that the shipped CLI has no such path.
- Fail closed: an unwrap error, an `ErrProtocol` answer or an unreadable store stops the service. It never generates a new KEK or starts an empty store by itself. A fresh KEK is made only in a recorded install window.
- At the switch from a pilot key file:
  1. generate a fresh KEK;
  2. wrap it to the posted fingerprint;
  3. check one unwrap round trip;
  4. delete the pilot key and the pilot store. They are not migrated.

## Limits

- Everything runs as one macOS user, so this is a barrier against casual and accidental use, not a wall. A separate OS user for the service is the real isolation.
- The binding is to code, not path. In CDHash mode a same-user process can put
  another binary at the install path and start the bound service's rebind.
  Certificate mode preserves its pins. Neither mode proves repository review or
  release authorization; those remain the release-signing boundary. Compare the
  audit chain head against the externally retained checkpoint.
- Reinspection detects changed or unidentifiable code between its two
  observations, including exec on a preserved socket. It does not atomically
  prevent a process from executing another image after the final observation.
- The audit chain shows an edit inside the log. A same-user rewrite of the whole log passes its own chain, so compare the head with the posted one.
- The existing broker is ad-hoc signed. A rebuilt broker is a new code identity,
  and with UI disabled the key's ACL can refuse it silently. This source
  extraction supplies no replacement installer: retain the existing installed
  broker and use its qualified update procedure in a planned owner sitting.
  Building a local candidate does not authorize replacing or repointing
  `~/.local/bin/mac-keyvault-kek`, re-provisioning keys or changing their ACLs.
- The key is non-extractable. If the login Keychain is reset or the item is deleted, the envelope cannot be opened again. A service using this must be able to rebuild its store, or keep a recovery envelope elsewhere.
- First provisioning trusts the public key the operator reads with `create` or `pub`. The service wraps only to the fingerprint posted with the window record.
- The envelope file and the broker binary are same-user files. Rewriting both lets a process feed the service a KEK of its choice (not the real one). Only the service's authenticated store refuses it, so a service must never start a new store on its own after an unwrap.

## Tests

- `pkg/kekclient`:
  - envelope round trip;
  - tamper and foreign-key refusal;
  - strict parsing;
  - requirement allowlist;
  - check value;
  - client refusals of answers outside the contract, including a broker that answers a KEK of its choice.
- `internal/keyvault/kek`: the broker over keyvault's Manager with an in-memory backend:
  - bound caller answered;
  - other or injectable callers refused;
  - tampered, foreign or mismatched envelopes refused;
  - missing, expired and unusable keys refused;
  - malformed requests;
  - no answer without the audit log;
  - rebind and its refusals;
  - the audit chain.
- `TestCodeInspectorReadsSignatures` checks the real inspector against binaries signed by codesign in four variants, and against a changed binary and a symlink.
- Certificate conformance covers exact and successive-build matches, wrong
  certificate/identifier and hardening refusals, immutable rebind mode and
  audit failure with no KEK. These use an in-memory vault. Native public-code
  certificate fixtures and an owned exec-on-preserved-socket fixture qualify
  signature facts separately; neither substitutes for installed service-pair
  acceptance. Run the fake-backed suite through
  `scripts/keyvault-test-confined.sh` and the opt-in
  [code-identity runner](../README.md#tools-and-local-build) separately. The runner's `run`
  mode applies the exec-level wrapper. Its public-certificate case verifies the
  specific trust refusal and absence of attested facts because that wrapper
  denies trustd. For the required read-only certificate positive, run from the
  repository root:

  ```sh
  CGO_ENABLED=1 go build -p 1 -o .temp/keyvault-codesigntest ./tools/codesigntest
  MAC_KEYVAULT_SKIP_KEYCHAIN=1 KEYVAULT_CODESIGN_TESTS=1 .temp/keyvault-codesigntest public-certificate
  ```

  The runner executes the tagged `TestSandboxCanary` first and checks that the
  init-level gate applied and the read-only nonexistent-item lookup was
  refused. That gate permits trustd and covers Go init onward. Review native
  startup inputs separately. The certificate case then verifies the public
  certificate and identifier, their binding, and both mismatch refusals. This
  mode uses public files and an owned Unix socket. It performs no Keychain
  write, signing or trust change. The shared lock and retained-tree cleanup
  apply to both modes. Preserve a verdict per lane. Unavailable native positive
  coverage blocks certificate acceptance.
- `TestSecurityStoreDecryptOpensGoEnvelope` opens a Go-sealed envelope with a real non-extractable Keychain key and refuses tampered ones. Like every real-Keychain test, it runs only in an attended sitting.
