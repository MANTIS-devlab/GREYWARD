# MailCraft on GREYWARD

GREYWARD installs the official MailCraft RPM from
[UCS-Care-Group/mailcraft](https://github.com/UCS-Care-Group/mailcraft).
The initial installer input is pinned in
[external-rpms.txt](../external-rpms.txt). It is installed from the offline
package closure using the upstream executable, app ID and MIME handlers.

The application menu and default desktop shortcut show **Mail** with
GREYWARD's envelope icon. The launcher initializes the native neutral dark
palette with a teal accent in a new profile and respects existing preferences.

The system timer checks GitHub for stable releases every six hours. It admits an
x86_64 RPM only after checking the Ed25519 signature over the upstream checksums
and the exact RPM digest, name, version and architecture. The two public keys
are pinned to MailCraft's upstream v0.14.0 release source. A key rotation beyond
those pins requires a GREYWARD update. Published local metadata remains usable
when the network is unavailable or a candidate fails verification.

The RPMs retain their original bytes. The root-owned file repository contains
only authenticated MailCraft packages and uses the existing DNF5 provider in
Security Center. The per-repository RPM signature option is disabled only for
this local repository because upstream signs the checksum list instead of the
RPM container. Fedora and other repositories keep their existing settings.
MailCraft's supported administration flag delegates updates to the system;
Security Center uses its normal update approval or configured automatic policy.
