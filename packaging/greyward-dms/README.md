# GREYWARD DMS candidate package

The [migration tracker](../../docs/architecture/DMS_1_6_MIGRATION_PLAN.md) owns
architecture and acceptance. [dms-release.json](../../environment/production/dms-release.json)
is the canonical source, dependency, patch and compatibility receipt.

Build in Fedora 44 with the exact build packages in that receipt. Acquire the two
immutable archives separately, verify their SHA-256 values, and place them in an
input directory. The build never downloads dependencies. Use an unprivileged
builder inside an empty network namespace, with a new writable output directory:

```bash
sudo unshare --net runuser -u builder -- \
  bash packaging/greyward-dms/build.sh /srv/dms-inputs /srv/dms-output-new
```

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
