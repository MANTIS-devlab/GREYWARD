# Development-only build tooling

This directory contains generic package-building helpers, including
`build-security-center.sh`. It is not an installed-system authority.
Private VM provisioning and account/access configuration are omitted from public
source. Contributors supply their own isolated Fedora builder and authentication.
The installed system is defined by `environment/production/` and package owners.
