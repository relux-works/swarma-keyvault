// Package reviewedsession contains source-only components of the accepted
// so59uu r2 contract (design SHA-256
// 3c7e28420d12efeabef1f1bf80d67956cbe5a8f28c39e1a335fe00e33244872f).
//
// There is deliberately no public constructor, signing method, CLI, transport,
// snapshot importer, or admission loader. The actual protected admission schema,
// script/transport custody, native execution custody and pinned timezone artifact
// are not supplied. A normalized receipt is comparison data, never proof of
// authentication or owner consent. These components cannot enable a sitting.
//
// All types are package-private to keep this partial source implementation from
// becoming an alternative public interface before the missing contracts arrive.
package reviewedsession
