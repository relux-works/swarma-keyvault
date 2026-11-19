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
- The native Keyvault registration/create path, protected account-token storage, current code-admission policy, and owner-approved session policy remain unimplemented and unqualified. The proposed no-per-key-presence mode is available only after an owner-sitting deployment explicitly admits the finite K3 management policy; otherwise no unattended issuance is allowed.
