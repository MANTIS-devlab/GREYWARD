# GREYWARD development overlay

This directory contains access and tooling used to build and operate the
disposable `GREYWARD-DEV` VM. It is not part of the installed GREYWARD system.

The overlay may contain:

- the temporary `stendev` SSH bootstrap account;
- passwordless sudo for the controlled development VM;
- SSH and Hyper-V guest services;
- compiler, packaging, debugging, and graphics-gate tools;
- the Packer communicator and developer deployment loop.

The factory order is explicit: install the production system, add the
factory-only component build tools when needed, then leave the development
overlay on the disposable development VM. A future installed image does not
consume this directory.
