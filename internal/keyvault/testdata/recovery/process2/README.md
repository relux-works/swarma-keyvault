# Public process/2 recovery fixtures

These software-only fixtures exercise complete-pair validation and the strict
versioned fd5 custody-frame codec. They do not establish Keychain identity,
ACL, owner presence, native admission, or hardware behavior.

The frozen v1 inputs remain at `../v1-public-record.json` and
`../v1-public-ciphertext.json`. The two v2 cases are:

| Fixture | Root/Nostr service | Namecoin service | Recovery version | Nostr version | Namecoin version |
| --- | --- | --- | ---: | ---: | ---: |
| `v2-equal-service` | `same-fixture` | `same-fixture` | 7 | 4 | 9 |
| `v2-distinct-service` | `nostr-fixture` | `namecoin-fixture` | 7 | 4 | 9 |

The fixtures were produced by the existing `RecoveryManager.Create` path and
`recoverySeal`, with the public `recoveryFixturePhrase` test vector and test-only
software wrapping keys. Envelope ephemeral keys come from the production
`crypto/rand` path. The files contain public record, account-pin, selection,
sidecar and ciphertext bytes only. No mnemonic, recovered secret, real key,
Keychain item or hardware output is included.

`v2-fixtures.json` records SHA-256 and byte length for each artifact, plus the
independently reconstructed v2 binding preimages and expected digests for both
purposes and service layouts. The test constructs the preimage from the literal
domain, namespace, physical account, logical account, canonical record bytes
and wrapping point, then compares its digest with the production binding.

Positive coverage includes the frozen v1 pair and both v2 service layouts.
Negative controls mutate either ciphertext, cross-pair v2 material, stale the
sidecar against a changed record, alter account-pin bytes or identity, mismatch
the selected group/account/policy, and corrupt sidecar/record canonicality.
