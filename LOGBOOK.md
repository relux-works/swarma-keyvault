# Flight Logbook

> Institutional memory. Concise, factual, high-signal.
> Newest entries first. One block per insight.

## 2026-11-13

### 0322 — Qualification driver tool discovery
- ROOT CAUSE: Go `-trimpath` clears embedded `runtime.GOROOT`; relying on it rejects a retained qualification driver before artifact creation.
- FIX: `tools/recoverybuild/root_qualification.go` resolves an absolute `go` through PATH; ambient GOROOT and exact toolchain-version refusals remain.
- STATUS: Source prepared; executable validation and native artifact generation pending.
