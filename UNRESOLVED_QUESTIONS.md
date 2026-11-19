# Unresolved questions

## Root storage ACL forms: decided, with what remains open

The owner and writer ACL forms are an explicit allowlist taken from attended native
evidence, stated in `docs/root-storage-acl-policy.md` and implemented in
`internal/rootqualification/policy.go`. It admits two forms (the access object built
in memory, and the item as the Keychain stores it), each through its own entry point,
and refuses everything else; it is never learned during production use. The refuse-all
default is kept only as the fallback if the allowlist cannot be built.

Still open:

- The stored form of an item created with the production descriptor is a prediction
  from the public-marker item that was observed. It has to be observed on a real
  production item before the owner's own key is stored.
- Whether the Integrity ACL's description differs per item (it is admitted by a
  64-hex pattern) needs a second observation.
- The encrypt ACL's absent application restriction is acceptable for the
  secret-release boundary only, and the empty change list means no preauthorized ACL
  writer; neither establishes sole-writer integrity of the item's envelope or public
  metadata, and no native write, overwrite or delete qualification has been run (see
  `docs/root-storage-acl-policy.md`).
- Forms on other macOS versions are unknown and refused until observed and reviewed.

## Agent identity enrollment and request keys

- Pulse's owner-selected identity-names-v2 amendment still marks its field, version, and resolver proposals as requiring acceptance before implementation. Pulse projections are unsigned and report source freshness as unknown; they do not prove that a card revision is accepted or current. What exact accepted card and reservation projection will the native enrollment authority consume? Until that representation is accepted and available, live registration and request-key creation refuse.
- The owner decision dated 2026-11-19 scopes the custody arrangement to the owners' accepted homeserver deployment and is recorded by date in `docs/agent-enrollment.md`; Link decision 0001 is pinned there. The immutable Link record for this custody decision is pending. Other homeservers need their own owner decision and acceptance; this proposal makes no deployment-wide claim and still refuses live registration.
- The authenticated mechanism by which the custody executable is authorized to use the selected homeserver's administrative route (B2) has not been named and accepted. Until it is, registration refuses before network submission; an unauthenticated route or local/remote relaying process is not permitted.
- The native Keyvault registration/create path, protected account-token storage, current code-admission policy, and owner-approved session policy remain unimplemented and unqualified. Per-key owner presence may be omitted only after an owner-sitting deployment explicitly admits the finite Keyvault management policy. That policy never replaces the exact owner-issued operation authorization required by KEY-MAP K3; otherwise unattended issuance refuses.
- Use or release of the account token after enrollment is outside this contract and refuses until a separate accepted contract defines it.
