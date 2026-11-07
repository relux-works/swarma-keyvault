# Pinned lab build inputs

`pinned-lab.bundle` contains the separately admitted lab verifier and signer
commits, with `dffe3ac5c86e2e8869efc3b869d35f845e1bd71a` as its prerequisite.
The hosted workflow checks out that public base, verifies the bundle SHA-256,
and checks each exact source tree before building the binaries:

| Role | Commit | Tree |
| --- | --- | --- |
| Verifier | `12b3ffac1993cc5b35074b569018b4db7c9bbd82` | `a553906c37721d8f2adbdb1051cf1cef0eb54c49` |
| Signer | `1045aac3ea204722aaaf0e60dac69eb8f622a7fb` | `b129a24428cdf5f2cc56fa5d9f27749c4a12065a` |

These commits are bundled because they are independent lab inputs, rather than
public branch tips. The candidate CLI is never substituted for the verifier.
Only the composition bridge is built from the candidate source. All builds
retain their committed module versions and checksums; missing fixtures fail the
full race suite. The bundle contains source objects, not executable fixtures.

To recreate the bundle from a repository containing the admitted objects:

```sh
git update-ref refs/fixtures/verifier 12b3ffac1993cc5b35074b569018b4db7c9bbd82
git update-ref refs/fixtures/signer 1045aac3ea204722aaaf0e60dac69eb8f622a7fb
git bundle create pinned-lab.bundle refs/fixtures/verifier refs/fixtures/signer \
  ^dffe3ac5c86e2e8869efc3b869d35f845e1bd71a
```

Repacking may change bundle bytes. Any replacement requires verification of
the commit/tree bindings and an updated workflow SHA-256.
