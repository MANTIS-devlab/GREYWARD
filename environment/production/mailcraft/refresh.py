#!/usr/bin/python3
"""Expose new signed upstream MailCraft RPM to the native DNF provider."""

import base64
import hashlib
import json
import re
import subprocess
import tempfile
import urllib.parse
import urllib.request
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

PROJECT = "UCS-Care-Group/mailcraft"
API = f"https://api.github.com/repos/{PROJECT}/releases/latest"
DOWNLOADS = f"https://github.com/{PROJECT}/releases/download"
STATE = Path("/var/lib/greyward/mailcraft")
RPM = "/usr/bin/rpm"
CREATEREPO = "/usr/bin/createrepo_c"
VERSION = re.compile(r"(?:0|[1-9][0-9]{0,5})(?:\.(?:0|[1-9][0-9]{0,5})){2}")
RPM_NAME = re.compile(rf"mailcraft-({VERSION.pattern})-linux-x86_64\.rpm")
HOSTS = {"api.github.com", "github.com", "release-assets.githubusercontent.com", "objects.githubusercontent.com"}
RPM_LIMIT = 128 * 1024 * 1024

# Active key and spare pinned to the upstream v0.14.0 RELEASE_KEYS.
KEYS = (
    "Mu5RF5oJpFhDGfa5wpgznC39tDC8vbUbyNkiAMdluPQ=",
    "XV6WRgW06/mGhZCHhFVKMIEZDmLevQduZPLSj/UW5zI=",
)


class GithubRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        url = urllib.parse.urlsplit(newurl)
        if (url.scheme != "https" or url.hostname not in HOSTS
                or url.username is not None or url.password is not None or url.port not in (None, 443)):
            raise ValueError("Unapproved MailCraft release redirect")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def fetch(url, limit, output):
    request = urllib.request.Request(url, headers={"User-Agent": "GREYWARD-MailCraft-Updates"})
    remaining = limit
    with urllib.request.build_opener(GithubRedirects()).open(request, timeout=30) as response:
        while chunk := response.read(min(1024 * 1024, remaining + 1)):
            remaining -= len(chunk)
            if remaining < 0:
                raise ValueError("MailCraft release file exceeds the size limit")
            output.write(chunk)


def version(text):
    if not VERSION.fullmatch(text):
        raise ValueError("Expected a stable MailCraft version")
    return tuple(map(int, text.split(".")))


def release_version(data):
    tag = data.get("tag_name")
    if (data.get("draft") is not False or data.get("prerelease") is not False
            or not isinstance(tag, str) or not tag.startswith("v")
            or data.get("html_url") != f"https://github.com/{PROJECT}/releases/tag/{tag}"):
        raise ValueError("Invalid official MailCraft release")
    version(tag[1:])
    return tag[1:]


def signed_digest(sums, signature, filename, keys=KEYS):
    signature = base64.b64decode(signature.strip(), validate=True)
    if len(signature) != 64:
        raise ValueError("Invalid MailCraft release signature length")
    for key in keys:
        try:
            Ed25519PublicKey.from_public_bytes(base64.b64decode(key, validate=True)).verify(signature, sums)
            break
        except InvalidSignature:
            continue
    else:
        raise ValueError("MailCraft release signature is not trusted")
    pattern = rb"([0-9a-f]{64}) [ *]" + re.escape(filename.encode("ascii"))
    matches = [m[1].decode("ascii") for row in sums.splitlines() if (m := re.fullmatch(pattern, row))]
    if len(matches) != 1:
        raise ValueError("Signed MailCraft checksums do not identify the RPM exactly once")
    return matches[0]


def file_digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def rpm_fields(command):
    return subprocess.run(
        [RPM, *command, "--qf", "%{NAME}\t%{EPOCHNUM}\t%{VERSION}\t%{ARCH}\n"],
        check=True, capture_output=True, text=True, timeout=30,
    ).stdout.strip().split("\t")


def refresh(state=STATE):
    installed = subprocess.run([RPM, "-q", "--quiet", "mailcraft"], check=False, timeout=30)
    if installed.returncode != 0:
        print("MailCraft is not installed")
        return
    _, _, installed_version, _ = rpm_fields(["-q", "mailcraft"])
    repo = state / "repo"
    repo.mkdir(exist_ok=True)
    marker = state / "published-version"
    previous = marker.read_text().strip() if marker.is_file() else None
    metadata = repo / "repodata/repomd.xml"
    with tempfile.TemporaryDirectory(dir=state) as temporary:
        scratch = Path(temporary)
        release = scratch / "release.json"
        with release.open("wb") as output:
            fetch(API, 512 * 1024, output)
        new_version = release_version(json.loads(release.read_bytes()))
        if (version(new_version) <= version(installed_version)
                or previous and (version(new_version) < version(previous)
                                 or new_version == previous and metadata.is_file())):
            print("MailCraft is current or already staged")
            return

        filename = f"mailcraft-{new_version}-linux-x86_64.rpm"
        base_url = f"{DOWNLOADS}/v{new_version}/"
        for name, limit in (("SHA256SUMS.txt", 64 * 1024), ("SHA256SUMS.txt.sig", 256)):
            with (scratch / name).open("wb") as output:
                fetch(base_url + name, limit, output)
        expected = signed_digest(
            (scratch / "SHA256SUMS.txt").read_bytes(), (scratch / "SHA256SUMS.txt.sig").read_bytes(), filename,
        )
        published = repo / filename
        rpm = published if published.is_file() else scratch / filename
        if not rpm.is_file():
            with rpm.open("wb") as output:
                fetch(base_url + filename, RPM_LIMIT, output)
        if file_digest(rpm) != expected:
            raise ValueError("MailCraft RPM does not match the signed checksum")
        if rpm_fields(["-qp", str(rpm)]) != ["mailcraft", "0", new_version, "x86_64"]:
            raise ValueError("Unexpected package identity in signed MailCraft RPM")
        if rpm != published:
            rpm.chmod(0o644)
            rpm.replace(published)
        package_list = scratch / "packages.txt"
        package_list.write_text(filename + "\n")
        subprocess.run(
            [CREATEREPO, "--quiet", "--update", "--retain-old-md-by-age", "7d",
             "--pkglist", str(package_list), str(repo)],
            check=True, timeout=90,
        )
        (scratch / "published-version").write_text(new_version + "\n")
        (scratch / "published-version").replace(marker)

    packages = sorted(
        (entry for entry in repo.iterdir() if RPM_NAME.fullmatch(entry.name)),
        key=lambda entry: version(RPM_NAME.fullmatch(entry.name)[1]),
    )
    for obsolete in packages[:-3]:
        obsolete.unlink()
    print(f"Verified MailCraft {new_version} is available through DNF")


if __name__ == "__main__":
    try:
        refresh()
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        raise SystemExit(f"Could not refresh MailCraft: {error}") from error
