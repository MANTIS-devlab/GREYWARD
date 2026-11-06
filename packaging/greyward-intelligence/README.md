# Local behavioral sensor package

See [architecture, operations and limits](../../docs/security-center/BEHAVIORAL_INTELLIGENCE.md).
`source.json` pins upstream source/BPF archives, the Go dependency locks and the
zero-fuzz BTF compatibility patch. Supply verified archives to `build.sh`;
the builder checks digests and builds userspace from source. Do not replace
these inputs with an unverified newer release. The unit owns a separate BPF
prefix and exposes no TCP control server. This local package is not a public
release. For the locally requested 0.5.4 image, it is an explicit verified RPM
input; see [image composition](../../docs/architecture/ISO_CREATION.md#054-sophon--2-november-2026).
Generated policies carry a private digest receipt: first-boot account refresh may
replace only unmodified generated files, never administrator edits. Unsupported
sensing is reported as unavailable and is not a login prerequisite.
