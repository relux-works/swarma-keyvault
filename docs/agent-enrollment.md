# Agent identity enrollment and request-key contract

Contract identifier: `agent-enrollment/1`.

Status: **PROPOSED**. This document defines a future Keyvault contract. It is not an installed interface or permission to register an account, create a key, or sign. Native custody, accepted-card resolution, implementation, qualification, and adoption remain separate gates.

## Scope

This contract covers an owner-created agent identity, its homeserver account, and the identity's Keyvault-held request key. The request key is a per-identity secp256k1 BIP-340 key for the separately specified typed request operations. It is distinct from the standalone Nostr family, owner keys, child-issuer keys, Namecoin keys, and Matrix end-to-end encryption keys.

This proposed contract does not generalize custody decisions across deployments. The administrative route, account-token custody, and session policy below apply only to the owners' accepted homeserver deployment under the decision dated 2026-11-19. Other homeservers require their own owner decision and acceptance. The dated decision and pinned Link decision 0001 are listed under [Sources](#sources); the immutable Link record of the custody decision is pending. Until the deployment-specific sources and route mechanism are accepted, this document remains **PROPOSED**, and registration refuses before network submission.

The owner alone creates the logical agent identity. A registration operation may run only for an agent with an accepted Pulse card and under the exact identity name selected for that card. For the specifically accepted deployment, the homeserver account is registered through its system administrator's administrative route; it does not use the owner's account token. Keyvault holds the resulting account token. This enrollment contract does not return it to an agent. Use or release after enrollment is outside this contract and refuses until a separate accepted contract defines it. Each agent can use only its own request key; private key material remains in Keyvault.

## Process and credential boundary

The owning Keyvault custody executable performs the homeserver registration request and native request-key creation within the same process. The new account token passes directly from the registration response to Keyvault's protected custody path in that process. It is stored as a Keyvault secret for the exact account and is not placed in an agent process, IPC request or response, CLI output, argument, environment, prompt, room, log, public record, journal, file outside Keyvault custody, client-library session or credential cache, password custody, crash report, or hash preimage of public data.

The enrollment hook is an IPC client. It supplies no registration credential and receives neither the new account token nor private key material. Any process other than the custody executable, local or remote, that performs registration and relays the token to Keyvault is refused. A two-process design requires a separately accepted authenticated secret-channel contract before implementation.

For the specifically accepted deployment, the custody executable sends the registration request itself over TLS that authenticates the selected homeserver's administrative route, and receives the response in that process. The mechanism that authorizes this Keyvault request (B2) is not yet named and accepted. Any credential the custody executable presents to the route is a Keyvault secret protected under the same item ACL as the account token; it appears in no IPC, argument, environment, log, or file. Until the route mechanism is named and accepted, registration refuses before network submission. The system administrator's administrative credential remains with the route and is never returned to the custody executable. The request carries no owner or administrator token. Neither credential is part of the public Keyvault record.

## Accepted identity binding

Before any registration or key effect, the operation is bound to one exact accepted card revision and one exact member identity. The accepted card revision, logical member, selected connection/server, full name, compact Matrix ID, and identity reservation must agree. Names are compared byte-for-byte; there is no alias, punctuation normalization, fallback domain, or name selection from CLI flags.

The member's exact full name must also equal, byte-for-byte, the identity returned by the H1 latch for the consumer. The reservation records that exact origin and consumer binding. A different identity or origin refuses before reservation and network submission. Keyvault writes no H1 record.

New names follow the owner-selected Pulse naming rule. From one reserved `(zone, product, project, role, star)` identity, the selected name pair is:

```text
full name:  <role-code>-<star>.<project>.<product>.<zone>
Matrix ID:  @<project>.<role-code>-<star>:<zone>
```

The v2 naming amendment and its card/resolver representation must be accepted before this route can use them. A syntactic name, desired card entry, local Pulse view, or formatted MXID is not itself an accepted reservation, proof of account existence, or operation authority.

Pulse is a read-only projection of selected card bytes. Its local caller value is unverified, and its source freshness is unknown. The custody operation therefore pins the accepted card digest and obtains the accepted identity binding from the authoritative card and reservation route. Pulse output may select and display the member; it cannot by itself establish card acceptance, current appointment, authenticated caller, account registration, or authority to perform an operation.

If the selected card revision is not accepted, its digest is stale or unavailable, the member is absent or ambiguous, the name/reservation does not match, or the selected server differs, the operation refuses before any remote or native effect.

## Keyvault native operation authorization

Use one predicate, **Keyvault native operation authorization**, for the complete native admission decision. It is true only when all of these facts hold at the time of the operation:

1. The operating system has authenticated the exact signed Keyvault custody executable against the currently protected code requirement, and the matched native pair is qualified for this operation.
2. A current, finite authorization issued by an owner's act (KEY-MAP K3), given at an OWNER-SITTING route or signed by an owner key that Keyvault verifies against its protected owner pin, permits exactly this registration-and-create operation for the bound identity, homeserver, fresh destination, key generation, session policy, and public write set. A manager, agent, run, enrollment hook, session grant, or earlier authorization cannot issue, renew, widen, or transfer it.
3. The authorization's accepted card digest, member identity, exact full name, compact Matrix ID, server, and reservation match the current selected inputs.
4. The explicit session policy is present, current, and satisfied.

Neither a code signature alone nor a Pulse value, name, environment variable, process ancestry, room membership, token possession, public metadata, general session grant, or agent-session action supplies this authorization. This contract does not isolate malicious processes under the same operating-system user: such a process may drive another identity's genuinely allowed client. This contract makes no same-user principal-isolation claim.

### Required session policy

The session policy must explicitly state the owner-presence rule and the scope in which it applies. For this request-key family, per-key owner presence may be omitted only after an owner-sitting deployment explicitly admits the finite Keyvault management policy for this exact create/use scope. That policy does not extend to owner keys or any other key family. Missing, unknown, expired, or mismatched policy refuses before the registration request. No default or inferred policy is allowed.

## Fresh destination and public writes

A fresh destination is an unregistered account on the selected homeserver together with an unused Keyvault identity/generation slot and no pending or unresolved earlier enrollment for that identity. Existing accounts, records, reservations, or incomplete transactions are not fresh destinations. The operation cannot adopt them, overwrite them, rotate them, or create a replacement automatically.

The operation's finite public write set is limited to the selected Keyvault record's public metadata projection:

| Public field | Bound value |
| --- | --- |
| Selection | Request-key family, purpose, and explicit generation |
| Identity | Exact accepted full name, compact Matrix ID, and selected homeserver name |
| Revision | The record's assigned revision for this generation |
| Public key | The x-only public key corresponding to the private request key |

These values are published only in the public metadata projection of the selected Keyvault record. No other record, room, message, homeserver profile, or public registry is a publication destination in this contract. The account token, registration credentials, private key, seed, or secret-derived value is never public metadata. Any additional field or destination requires a revised finite write set and renewed agreement.

## Transaction order and uncertain outcomes

Before the remote request, the custody executable durably records a nonsecret reservation for the original operation identity and immutable destination. It validates the accepted identity, Keyvault native operation authorization, session policy, fresh destination, and complete write set at reservation, then rechecks the actual peer, original principal or intent, authorization, expiry, revocation, and caps before account-token custody and immediately before native create. A failed recheck stops every later effect and leaves the enrollment incomplete and blocked.

The executable performs one registration through the accepted administrative route. Before protected custody, the response must contain an access token and the exact bound compact Matrix ID from the authenticated selected server. A missing, malformed, mismatched, other-user, other-server, or existing-account response is an **UNKNOWN** registration result: no account token is committed to protected custody, no request key is created, and the destination remains blocked. On a valid response, the executable creates the selected Keyvault request-key record. It publishes public metadata only after an authenticated, complete committed receipt exists for this exact original operation; an absent, incomplete, or different-operation receipt permits no publication. An exact replay returns the retained public result without a second registration, key creation, or write. No other account or generation may be selected implicitly. The enrollment hook receives only the public metadata projection. Private signing is available only to the bound agent through a separate accepted request-key use path.

An unknown registration result, lost token, interrupted key creation, or uncertain public-record write leaves the enrollment incomplete and its destination blocked. The vault does not retry registration, adopt an account, create a replacement key, rotate the generation, or claim that no remote effect happened. Only an owner's recorded act closes a blocked enrollment. A later registration is a new operation with a new owner-issued authorization and fresh destination; an unsettled reconciliation remains blocked.

## Contract controls

| Valid control | Required refusal or limit |
| --- | --- |
| Owner-issued authorization binds the exact operation, identity, server, generation, session policy, destination, and write set | A manager, agent, run, hook, session grant, earlier authorization, or authorization for another identity refuses before reservation and network submission; no remote or native effect follows |
| Accepted card identity and H1 latch identity, origin, and consumer match byte-for-byte in the reservation | Different identity or origin refuses before reservation and submission; Keyvault writes no H1 record |
| Exact signed custody executable and qualified matched pair under current protected policy | Wrong, unsigned, rebuilt, or unqualified executable refuses before private access |
| Explicit current session policy admitted by the owner-approved finite deployment | Missing or expired policy refuses; no inferred unattended mode, and it never replaces the owner-issued operation authorization |
| The custody executable uses TLS to authenticate the selected administrative route in the accepted deployment | Unauthenticated or different endpoint, unnamed/unaccepted B2 mechanism, or local/remote relaying process refuses before network submission |
| The authenticated selected server returns a token and the exact bound compact Matrix ID for one fresh destination | Missing, malformed, mismatched, other-user, other-server, or existing-account response is UNKNOWN; no token is committed, no key is created, and the destination stays blocked |
| One unused identity/generation and one fixed public write set are durably reserved; the predicate is rechecked before custody and create | Expired or revoked authorization, changed peer/principal/intent, or exceeded cap stops every later effect and leaves the enrollment incomplete and blocked |
| The exact original operation has an authenticated complete committed receipt before public metadata is written | Missing, incomplete, or different-operation receipt permits no publication; an exact replay returns the retained public result without a second effect |
| Only the public metadata write set is returned to the hook; the bound agent uses a separate accepted request-key path | A credential field supplied by the hook or token/credential in IPC, arguments, environment, logs, journal, any file written by the operation, client cache, password custody, crash report, or public-data hash preimage refuses; no later custody, create, or publication occurs, the result remains UNKNOWN, and the destination stays blocked |
| An owner's recorded act closes a blocked enrollment, after which a new operation has a new authorization and fresh destination | Timeout, agent/run/manager act, or unsettled reconciliation leaves it incomplete and blocked; no retry, replacement, rotation, or inference that the remote account was not created |

The contract permits source preparation against **PROPOSED** text only. It does not implement account registration or request-key issuance, qualify native code admission or token storage, prove live Pulse acceptance, or claim an attended or unattended operation has occurred.

## Related contracts

- [Nostr key custody](nostr.md) defines the separate standalone Nostr key family.
- [Companion enrollment proposal (LIP-0014)](https://github.com/relux-works/swarma-link-spec/blob/3dab5a68e56e31aa97d9e61085924771470ceda2/lips/LIP-0014-source-contract-proposals.md) defines the related request-side contract; its section 2.4 remains proposed and does not adopt this contract.
- [Pulse's new-agent naming rule](https://github.com/relux-works/swarma-pulse/blob/a60d2de03e2cccf1d13881bd19c4e144ba87bc48/agents/skills/swarma-pulse/references/naming.md) defines owner-selected full and compact names.
- [Pulse's identity-names-v2 amendment](https://github.com/relux-works/swarma-pulse/blob/a60d2de03e2cccf1d13881bd19c4e144ba87bc48/docs/specs/identity-names-v2.md) remains subject to its own acceptance and implementation gates.

## Sources

- Owners' decision, 2026-11-19, scoped to the owners' accepted homeserver deployment: identities are owner-created; the system administrator retains the registration administrative route; Keyvault holds each new account token; each agent receives only its own key; this contract lives in the Keyvault specification and the Link specification refers to it. The immutable Link record of this custody decision is pending.
- [Link decision 0001, scope of v0.1](https://github.com/relux-works/swarma-link-spec/blob/ec9119394878cad2efe423232a9a98aee3100a1d/decisions/0001-scope-of-v0-1.md) states that the grant envelope belongs to Keyvault and that the Link specification refers to its owning specification rather than restating it. The pinned file SHA-256 is `7fb0ee4ef2c78a07a6e3165b3d8d6c7d9496d1f252d2735094a2f03e68fec1af`.

The Link enrollment clause must reference the accepted `agent-enrollment/1` contract by its exact source revision and digest. Until that reference is accepted, the Link clause remains proposed and grants no registration, key-creation, or signing authority.
