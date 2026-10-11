# ISO source checklist

1. Read `docs/architecture/ISO_CREATION.md` and current status.
2. Prepare your own disposable Fedora builder and verify available storage.
3. Build matched component RPMs from verified upstream inputs and source receipts.
4. Use the generic `environment/image/build-iso.sh` command contract.
5. Verify embedded payload, offline dependencies, checksum and provenance.
6. Validate clean installation and live security boundaries separately.

Private factory accounts, access methods and machine-specific configuration are
not distributed. Do not infer installed-system acceptance from composition.
