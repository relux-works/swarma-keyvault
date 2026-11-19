# Agent identity enrollment and request-key contract

Contract identifier: `agent-enrollment/1`.

Status: **PROPOSED**. This document defines a future Keyvault contract. It is not an installed interface or permission to register an account, create a key, or sign. Native custody, accepted-card resolution, implementation, qualification, and adoption remain separate gates.

## Scope

This contract covers an owner-created agent identity, its homeserver account, and the identity's Keyvault-held request key. The request key is a per-identity secp256k1 BIP-340 key for the separately specified typed request operations. It is distinct from the standalone Nostr family, owner keys, child-issuer keys, Namecoin keys, and Matrix end-to-end encryption keys.

The owner alone creates the logical agent identity. A registration operation may run only for an agent with an accepted Pulse card and under the exact identity name selected for that card. The homeserver account is registered through the system administrator's administrative route; it does not use the owner's account token. Keyvault holds the resulting account token and never gives that token to an agent. Each agent can use only its own request key; private key material remains in Keyvault.

## Process and credential boundary

The owning Keyvault custody executable performs the homeserver registration request and native request-key creation within the same process. The new account token passes directly from the registration response to Keyvault's protected custody path in that process. It is stored as a Keyvault secret for the exact account and is not placed in an agent process, IPC request or response, CLI output, argument, environment, prompt, room, log, public record, or journal.

The enrollment hook is an IPC client. It supplies no registration credential and receives neither the new account token nor private key material. A separate local process may not register the account and forward its token to Keyvault under this contract. A future two-process design requires a separately accepted authenticated secret-channel contract before implementation.

The system administrator's administrative route remains the authority for account registration and retains its own administrative credential. The route authenticates the authorized Keyvault request without returning that credential to the custody process. The request carries no owner or administrator token. Keyvault receives only the new account's token. Neither credential is part of the public Keyvault record.

## Accepted identity binding

Before any registration or key effect, the operation is bound to one exact accepted card revision and one exact member identity. The accepted card revision, logical member, selected connection/server, full name, compact Matrix ID, and identity reservation must agree. Names are compared byte-for-byte; there is no alias, punctuation normalization, fallback domain, or name selection from CLI flags.

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
2. A current, finite management authorization permits exactly this registration-and-create operation for the bound identity, homeserver, fresh destination, key generation, session policy, and public write set.
3. The authorization's accepted card digest, member identity, exact full name, compact Matrix ID, server, and reservation match the current selected inputs.
4. The explicit session policy is present, current, and satisfied.

Neither a code signature alone nor a Pulse value, name, environment variable, process ancestry, room membership, token possession, or public metadata supplies this authorization. The accepted K3 request-level scope does not isolate malicious processes under the same operating-system user: such a process may drive another identity's genuinely allowed client. This contract makes no same-user principal-isolation claim.

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

The custody executable validates the accepted identity, Keyvault native operation authorization, session policy, fresh destination, and complete write set before the remote registration request. It then performs one registration through the authorized administrative route, receives the new account token in the same process, creates the selected Keyvault request-key record, and publishes only the listed public metadata. No other account or generation may be selected implicitly.

An unknown registration result, lost token, interrupted key creation, or uncertain public-record write leaves the enrollment incomplete and its destination blocked. The vault does not retry registration, adopt an account, create a replacement key, rotate the generation, or claim that no remote effect happened. Reconciliation and closure require an explicit owner act with recorded evidence. Any later registration is a new operation with a new authorization and fresh destination.

## Contract controls

| Valid control | Required refusal or limit |
| --- | --- |
| One accepted card digest, unique reserved member identity, matching server, current authorization and fresh destination | Stale/unaccepted card, ambiguous member, changed name/server, missing reservation, or substituted digest refuses before network submission |
| Exact signed custody executable and qualified matched pair under current protected policy | Wrong, unsigned, rebuilt, or unqualified executable refuses before private access |
| Explicit current session policy admitted by the owner-approved finite deployment | Missing or expired policy refuses; no inferred unattended mode |
| One unused identity/generation and one fixed public write set | Existing account/key, pending enrollment, changed generation, extra public field, or different destination refuses without overwrite or automatic recovery |
| Registration response and native create remain in the owning custody process | A separate registration process or token handoff is outside this contract and needs a new accepted secret-channel contract |
| Successful creation returns only the agent's public key and its own typed signing capability | Private key, seed, account token, administrative credential, or another agent's key is never exported |
| Interrupted or unknown outcome remains incomplete and blocked | No retry, replacement, rotation, or inference that the remote account was not created |

The contract permits source preparation against **PROPOSED** text only. It does not implement account registration or request-key issuance, qualify native code admission or token storage, prove live Pulse acceptance, or claim an attended or unattended operation has occurred.

## Related contracts

- [Nostr key custody](nostr.md) defines the separate standalone Nostr key family.
- [Pulse's new-agent naming rule](https://github.com/relux-works/swarma-pulse/blob/main/agents/skills/swarma-pulse/references/naming.md) defines owner-selected full and compact names.
- [Pulse's identity-names-v2 amendment](https://github.com/relux-works/swarma-pulse/blob/main/docs/specs/identity-names-v2.md) remains subject to its own acceptance and implementation gates.

The Link enrollment clause must reference the accepted `agent-enrollment/1` contract by its exact source revision and digest. Until that reference is accepted, the Link clause remains proposed and grants no registration, key-creation, or signing authority.
