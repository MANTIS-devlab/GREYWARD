"""Text-only clipboard observer used by the user Security Context service."""

from __future__ import annotations

import json
import sys

from greyward_security_context.privacy_capsule import clipboard_classification


MAX_CLIPBOARD_TEXT_BYTES = 256 * 1024


def classify_stdin(stream) -> dict:
    """Read one clipboard value and return metadata only."""

    raw = stream.buffer.read(MAX_CLIPBOARD_TEXT_BYTES + 1)
    if len(raw) > MAX_CLIPBOARD_TEXT_BYTES:
        return {"category": None}
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return {"category": None}
    category = clipboard_classification(text)
    del text
    del raw
    return {"category": category}


def main() -> int:
    # stdout is consumed by the parent observer.  No clipboard value is ever
    # emitted, logged, or sent over D-Bus.
    print(json.dumps(classify_stdin(sys.stdin), separators=(",", ":")), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
