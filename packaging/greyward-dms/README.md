# GREYWARD DMS candidate package

The [migration tracker](../../docs/architecture/DMS_1_6_MIGRATION_PLAN.md) owns
architecture and acceptance. [dms-release.json](../../environment/production/dms-release.json)
is the canonical source, dependency, patch and compatibility receipt.

Build in Fedora 44 with the exact build inputs in that receipt. Acquire all
listed immutable archives separately, verify their SHA-256 values, and use an
input directory. The build never downloads dependencies. Use an unprivileged
builder inside an isolated network namespace with only loopback enabled, and a
new writable output directory. Keep TMPDIR short enough for Unix sockets:

```bash
sudo unshare --net sh -eu -c 'ip link set dev lo up; exec "$@"' greyward-isolated-build \
  runuser -u builder -- bash packaging/greyward-dms/build.sh /srv/dms-inputs /srv/dms-output-new
```

An optional third argument selects an explicit candidate manifest for that build
only. It is copied into the isolated package source bundle; the production
manifest and active selector are unchanged. Source/vendor names, minimum Go,
shared QML directory and version linker metadata derive from that receipt.
An optional `build.rpmRelease` adds a positive numeric suffix to the runtime
generation (for example `7.2` for `v2.0.0-7`) for an ordinary-plugin-only package
correction. The selector and protected generation stay unchanged. Before live
installation, compare extracted executable/shell/helper payloads against the
installed generation and require byte identity. `build.packageOnlyRuntime` pins
all three executable digests; the RPM build rejects drift before providing the
predecessor's exact DMS runtime dependency. This lets the existing Enrollment
package remain installed without rebuilding or changing protected inputs.
Changes to those inputs require
a new matched runtime generation and its normal protected migration. Enrollment's
exact RPM dependency for a new matched build and the image identity-reuse guard
consume the package pin. Fresh-image staging still requires that newly matched
Enrollment RPM; runtime compatibility does not waive image checks.

The accepted 27 October plugin presentation is package revision `7.11`.
For an offline build without rebuilding identical executables, run
`build-artwork-update.py --plugins-only BASE-RPM NEW-OUTPUT` as an unprivileged
builder. `build.pluginUpdate` locks predecessor NEVRA/RPM/shell/plugin digests
and exactly the two visual QML adapters plus their versioned manifest. Collector,
state palette/model, executables and protected shell stay identical. Undeclared
changes or stale source hashes refuse the build. The normal `build.sh` route
remains available and consumes the same source lock. Both routes provide the
verified predecessor's exact DMS dependency for an existing Enrollment 84;
future image builds use the new matched Enrollment 85 requiring DMS 7.11.
This plugin-only update does not require protected-profile migration or logout.

The explicit artwork-only successor is different from an ordinary-plugin-only
update: `build.artworkUpdate` pins the complete accepted predecessor RPM and its
shell digest. `build-artwork-update.py BASE-RPM NEW-OUTPUT` runs unprivileged,
verifies the three unchanged executables, unchanged plugin/source/patch locks,
and changes only the canonical Settings SVG plus its receipt. It does not build
from arbitrary installed files or load code from the predecessor. Normal full
source builds remain available. The successor requires a newly matched
Enrollment RPM for image composition and the protected-profile migration at
activation; the shared selector is not evidence that the old profile matches.
An incompatible executable, extra changed artwork path, stale icon copy or
different predecessor stops this route. No public artifact is published by it.
A candidate can pin a separately verified Go toolchain extracted only inside
its new build tree. The host compiler is unchanged. Reviewed shell additions
have a closed inventory and individual hashes; existing upstream files can only
change through exact-preimage patches. Incomplete activation receipts are
refused by every selector path, including compatibility projection.
The active 1.6 build remains the default. The 2.0 physical trial is installed;
hardware, recovery and release acceptance remain pending; see the
[migration authority](../../docs/architecture/DMS_2_0_MIGRATION.md).

The spec verifies inputs and matching backend source inventories, assembles
exact patch preimages/hunks, preserves upstream vanilla shell generation, runs
backend tests, and builds with `distro_binary withshell`. The Go linker strips
the binary; RPM must not strip it again after its digest is recorded. An empty
generated `.dankrev` input removes the upstream generator's enumeration race;
the unchanged generator computes the final key. That key is not an integrity
receipt.

Inspect the RPM, its installed receipt, dependencies and licenses before
candidate activation. `/usr/libexec/greyward-dms-verify` checks all file hashes
and the root-owned selected tuple. Startup and health use full verification.
IPC uses `--selection-only` to check selection, ownership and tuple while
reaching the running shell already verified at startup.

For an upgrade, review the precise source delta, update immutable pins and the
tested tuple, port only justified patches, regenerate their ordered preimages
and the shell digest, and run the migration fixtures plus offline package/session
gates. Changed preimages, extra backend files, offsets, fuzz, unknown patches or
file-count drift refuse assembly. Do not edit a generated installed shell.
Increment the GREYWARD package revision for a promoted replacement; retain the
previous runtime and separately backed-up config, state and caches.

The disposable VM switching and measurement tools are under `tools/greyward-dev/`.
They are not a production deployment, authentication or release-certification tool.
