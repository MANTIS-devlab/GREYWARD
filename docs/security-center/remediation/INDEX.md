# Security Center remediation history

This directory contains dated, evidence-backed records of scoped Security Center
remediation work. Entries distinguish source verification from runtime evidence
and do not turn planned work into a current claim.

| Record | Scope | Status |
| --- | --- | --- |
| [2026-09-07 F07 Black Box terminal](2026-09-07-f07-blackbox-terminal.md) | Replace Kitty/Tabby with Fedora-native Black Box under the GREYWARD-owned Terminal identity, while preserving the exact Oh My Zsh/Powerlevel10k shell setup | **F07 — FIXED + RUNTIME VERIFIED** on `.149`; no reboot used |
| [2026-09-07 F07 terminal migration](2026-09-07-f07-terminal-migration.md) | Historical superseded migration from Tabby to Kitty; retained as evidence for the intermediate state | Historical |
| [2026-09-07 immutable audit remediation](2026-09-07-immutable-audit-remediation.md) | Historical F01-F07 audit record covering threat-policy authorization, crypto baseline, Flatpak truthfulness, OpenSnitch projection boundary, text editor, OpenVPN backend, and the former Tabby sandbox | Historical snapshot; later F07 terminal evidence is superseded by the Black Box record |
| [2026-09-01 production payload verification](2026-09-01-production-payload.md) | Complete production image inputs, Security Center RPM/tool staging, development-overlay separation, and first-setup service enablement | Complete stage and Alpha runtime revalidated; fresh ISO install remains open |
| [2026-09-01 production ISO pipeline remediation](2026-09-01-production-iso-pipeline.md) | Security Center freshness binding, Anaconda account lifecycle, live-pipeline retirement, and Fedora/GREYWARD installer branding | Live pipeline retired; direct installer source implemented; clean runtime validation pending |
| [2026-09-01 full functional/runtime audit](2026-09-01-functional-runtime-audit.md) | Broad Security Center workflow, privilege boundary, provider, filesystem, state, notification, and degraded-state audit | Source remediation completed; canonical GREYWARD-DEV runtime gate blocked |
| [2026-09-01 Privacy workflow remediation](2026-09-01-privacy-workflow.md) | Authoritative privacy-profile synchronization, pending/failure state, DMS convergence, and fixed export destination feedback | SC-PRV-001 source-fixed/runtime gate blocked; SC-PRV-002 export runtime check passed; package pending |
| [2026-09-01 Updates workflow remediation](2026-09-01-updates-workflow.md) | Current update precedence, normalized history, one phase presentation model, apply/reboot reconciliation, and offline-boot feedback | SC-UPD-001/002/003 fixed; DNF5 transaction 70 verified; patched Plymouth feedback awaits user-run update/reboot observation |
| [2026-09-02 essential PCI driver support](2026-09-02-essential-pci-driver-support.md) | Sysfs essential-device detection, Fedora modalias provider lookup, and normal DNF5 Updates integration | EASY; implemented with Fedora/GREYWARD-DEV runtime evidence and simulated unbound-device tests |
| [2026-09-01 Network Activity interaction remediation](2026-09-01-network-activity-interaction.md) | Pause/resume, authoritative filters, activity history interaction coverage, and bounded rule-action runtime validation | SC-ACT-001/002/003 and SC-NET-003 fixed; real Tauri WebDriver runtime verified |
| [2026-08-31 IPC and navigation remediation](2026-08-31-ipc-and-navigation.md) | Network rules, activity history, file-context IPC, and DMS routes | Implemented; runtime evidence recorded in the entry |
| [2026-08-31 File Security core workflow remediation](2026-08-31-file-security-core.md) | ClamAV lifecycle, scan accounting, File Activity, quarantine/restore, picker boundaries, and Safe Open handlers | Implemented; runtime validation status recorded in the entry |
| [2026-08-31 state truthfulness remediation](2026-08-31-state-truthfulness.md) | Network protection states, USBGuard enforcement, shared posture counts, and stale DMS context | Implemented; runtime validation status recorded in the entry |
| [2026-08-31 Recovery and package workflow remediation](2026-08-31-recovery-and-package-workflow.md) | Repository-specific Restic state, backup/restore operation truthfulness, typed restore candidates, and package validation cost | Implemented; final package evidence recorded in the entry |
