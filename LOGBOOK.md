# Flight Logbook

> Institutional memory. Concise, factual, high-signal.
> Newest entries first. One block per insight.

## 2026-11-13

### 0601 — Native test compilation
- ROOT CAUSE: Throwing assertions inside rethrowing buffer closures obscured closure inference; imported Security and helper status constants were ambiguous.
- FIX: Evaluate throwing anchor reads before assertions and qualify the SDK status fixtures. Inputs and rejection expectations remain unchanged.
- STATUS: Production compilation passed on the preceding candidate; revised test compilation remains pending.

### 0534 — Swift Security API imports
- ROOT CAUSE: Swift imports no-network and prompt-selector options as typed values; the signing-information C API's running-code argument needs an explicit Swift reference view.
- FIX: `NativeHelperCore.swift` keeps the running object alive across that API; qualification retains strict/offline flags and journal ACL inspection retains a zero prompt selector.
- STATUS: Source prepared; production/test compilation and native qualification remain pending.

### 0322 — Qualification driver tool discovery
- ROOT CAUSE: Go `-trimpath` clears embedded `runtime.GOROOT`; relying on it rejects a retained qualification driver before artifact creation.
- FIX: `tools/recoverybuild/root_qualification.go` resolves an absolute `go` through PATH; ambient GOROOT and exact toolchain-version refusals remain.
- STATUS: Source prepared; executable validation and native artifact generation pending.
