# Hosted verifier runner prerequisite

The non-race verifier job selects Ubuntu 24.04 amd64 and proposes installing
`bubblewrap=0.9.0-1ubuntu0.3` from Ubuntu's authenticated archive. This platform
tool pin is separate from the unchanged Go toolchain and go.sum dependencies.
The runner label selects an OS family, not an immutable image; retain the actual
image version in each run's evidence. If the package/version is unavailable,
setup fails; do not silently substitute a different version or runner.

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

If the hosted runner denies namespaces, its owner must provide a scoped AppArmor
policy permitting the installed `/usr/bin/bwrap` to create them, or select an
owner-qualified provisioned runner with the same isolation and explicit tool
version. This candidate does not install an AppArmor override, disable global
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
