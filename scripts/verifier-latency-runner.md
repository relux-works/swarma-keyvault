# Hosted verifier runner prerequisite

The non-race verifier job selects Ubuntu 24.04 amd64 and proposes installing
`bubblewrap=0.9.0-1ubuntu0.3` from Ubuntu's authenticated archive. This platform
tool pin is separate from the unchanged Go toolchain and go.sum dependencies.
The runner label selects an OS family, not an immutable image; retain the actual
image version in each run's evidence. If the package/version is unavailable,
setup fails; do not silently substitute a different version or runner.

Provisioning is **blocked pending runner-owner disposition**. The exact official
amd64 package has SHA256
`2461f1beee9cb04c8942739fe1a2b37e7b7c2a3d518f0779dc75f9245baa3094`.
Its `/usr/lib/sysctl.d/50-bubblewrap.conf` sets
`kernel.unprivileged_userns_clone=1`; its postinst invokes `sysctl --quiet`
with `--pattern` for that knob and `--system` when sysctl exists. This attempts
host-wide enablement where the kernel exposes the knob. Actual runner effect
is unknown; official package origin grants no exception to the contract against
global namespace policy changes. The workflow therefore exits 78 before setup,
preflight, provisioning or measurement. No package install or policy command is
authorized by this candidate.

An option for owner evaluation is a preprovisioned, exact-version qualified
runner whose existing namespace and AppArmor policies remain unchanged. Before
any source revision could select it, the owner must qualify its immutable image,
exact package provenance/version, unchanged policies and the same fail-closed
preflight. This is an unelected option, not a fallback or qualification claim.

The launcher requires bwrap before provisioning dependencies. It uses the same
`--unshare-all --clearenv` sandbox for a non-product preflight and measurement.
The preflight checks read-only source, toolchain, tools and dependency mounts,
0700 private scratch directories, a cleared credential environment and the
exact go.mod toolchain. Starting it also tests whether the runner permits the
required namespaces. A successful package install alone does not qualify them.
Dependency provisioning uses a new private cache, a cleared environment and
canonical public Go checksums. Product tests run offline in the sandbox.

Missing bwrap reports exit 127. A failed preflight retains its original stderr
and exit status, explicitly says no timing samples were collected and stops
before dependency provisioning or product startup. These are setup failures,
not measured latency failures. The pipeline retains nonzero exit status through
`pipefail`; the existing always-run summary step preserves any recorded output.

On exit, a bounded cleanup uses inherited descriptors for this invocation's
private state. It grants owner write permission only on owned directories after
execution, never on files or symlink targets, and refuses mount boundaries and
changed directory identities. Read-only sandbox mounts remain unchanged.
Cleanup has a 12-second timeout with a 2-second forced-termination bound,
100,000-entry limit and depth limit 128, without retries. A cleanup error is
reported separately; an existing nonzero primary exit is retained, while a
successful primary exit becomes 74. HUP/INT/TERM/PIPE exit 129/130/143/141 and run the
same cleanup. SIGKILL and machine loss cannot be trapped. Python 3 and GNU
timeout are runner-side cleanup prerequisites, checked before state creation.

If the hosted runner denies namespaces, stop for its owner to qualify a route
within the existing isolation and policy contract. This candidate does not
select another runner, install an AppArmor override, disable global
namespace restrictions, share networking, use sudo for tests or run the verifier
outside the sandbox. Package/policy disposition requires runner-owner review.
The namespace preflight must succeed on that runner before any measurement.

The offline shell fixtures in `tests/verifier-latency-confined-test.sh` check
missing-tool diagnostics, original namespace refusal status/stderr, cleanup and
no product startup. Their Go shim and any namespace refusal are explicitly
labelled; they are neither real toolchain nor performance qualification.

The product's 100ms fence and one measurement with exactly 40 samples per path,
nearest-rank p95 <=80ms and maximum <100ms, with zero retries, are unchanged.

Official platform references:

- [Ubuntu package inventory](https://packages.ubuntu.com/noble/amd64/bubblewrap/filelist)
- [Ubuntu package versions](https://packages.ubuntu.com/bubblewrap)
- [Ubuntu namespace and AppArmor policy](https://discourse.ubuntu.com/t/ubuntu-24-04-lts-noble-numbat-release-notes/39890)
- [Bubblewrap sandbox construction](https://github.com/containers/bubblewrap/blob/v0.9.0/README.md)
