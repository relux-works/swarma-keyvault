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
- Whether the encrypt ACL's absent application restriction is acceptable for a root
  item is a review question; the observation records it and does not settle it.
- Forms on other macOS versions are unknown and refused until observed and reviewed.
