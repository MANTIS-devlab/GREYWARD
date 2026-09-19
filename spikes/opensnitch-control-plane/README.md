# OpenSnitch control-plane spike

This isolated Session 2 proof is not production code. It implements the five-method OpenSnitch v1.8.0 UI gRPC service with upstream generated protobuf bindings and no Qt, OpenSnitch UI, or database dependency.

The disposable Fedora 44 validation bound the server to a protected Unix socket under /run, accepted the daemon Subscribe and Notifications stream, normalized real connection data, returned an always-persisted allow rule for curl, and returned a one-shot deny for Python. The daemon saved the allow rule in its own rule directory.

A production GREYWARD system control-plane service must own the Unix socket, authenticate the local daemon, bind the generated v1.8.0 protocol deliberately, translate only bounded fields into Security Context, and expose typed rule mutations. It must not import or ship UI code, copy history, or manage raw nftables.