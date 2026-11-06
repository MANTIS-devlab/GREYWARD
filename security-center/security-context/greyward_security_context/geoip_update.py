"""Monthly DB-IP Lite Country download; no observed IP ever leaves the machine."""
import datetime as dt
import gzip
import hashlib
import json
import os
from pathlib import Path
import tempfile
import time
import urllib.error
import urllib.request

import maxminddb

DIRECTORY = Path('/var/lib/greyward/geoip')
DATABASE = 'dbip-country-lite.mmdb'
ATTRIBUTION = 'IP Geolocation by DB-IP — https://db-ip.com — CC BY 4.0 — https://creativecommons.org/licenses/by/4.0/'
MAX_DOWNLOAD = 20 * 1024 * 1024
MAX_DATABASE = 40 * 1024 * 1024


class FixedOriginRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, url):
        if not url.startswith('https://download.db-ip.com/free/'):
            raise ValueError('Unexpected GeoIP download redirect')
        return super().redirect_request(request, fp, code, message, headers, url)


def fetch(month):
    url = f'https://download.db-ip.com/free/dbip-country-lite-{month}.mmdb.gz'
    request = urllib.request.Request(url, headers={'User-Agent': 'GREYWARD-GeoIP/1'})
    with urllib.request.build_opener(FixedOriginRedirect()).open(request, timeout=30) as response:
        payload = response.read(MAX_DOWNLOAD + 1)
    if len(payload) > MAX_DOWNLOAD:
        raise ValueError('GeoIP download exceeds its size limit')
    return payload


def atomic_json(path, value):
    fd, name = tempfile.mkstemp(prefix='.status-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as stream:
            json.dump(value, stream, sort_keys=True)
            stream.write('\n'); stream.flush(); os.fsync(stream.fileno())
        os.chmod(name, 0o644)
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def update(directory=DIRECTORY, today=None, download=fetch):
    today = today or dt.datetime.now(dt.timezone.utc).date()
    month = today.strftime('%Y-%m')
    directory = Path(directory)
    directory.mkdir(mode=0o755, parents=True, exist_ok=True)
    database, status = directory / DATABASE, directory / 'status.json'
    try:
        previous = json.loads(status.read_text())
    except (OSError, ValueError):
        previous = {}
    usable = False
    if database.is_file() and database.stat().st_size == previous.get('size'):
        try:
            with maxminddb.open_database(str(database)) as reader:
                usable = reader.metadata().build_epoch == previous.get('build_epoch') and all(
                    ((reader.get(address) or {}).get('country') or {}).get('iso_code')
                    for address in ('8.8.8.8', '2001:4860:4860::8888'))
        except (OSError, ValueError, RuntimeError):
            pass
    # Once the current monthly edition is installed, daily checks make no request.
    if previous.get('month') == month and usable:
        return {**previous, 'downloaded': False}
    temporary = None
    try:
        try:
            payload = download(month)
        except urllib.error.HTTPError as error:
            if error.code != 404:
                raise
            # The new edition can arrive after the start of a month. Retain the
            # last good edition and retry tomorrow; bootstrap from last month.
            month = (today.replace(day=1) - dt.timedelta(days=1)).strftime('%Y-%m')
            if previous.get('month') == month and usable:
                return {**previous, 'downloaded': False, 'pending_month': today.strftime('%Y-%m')}
            payload = download(month)
        fd, temporary = tempfile.mkstemp(prefix='.country-', dir=directory)
        import io
        with os.fdopen(fd, 'wb') as output, gzip.GzipFile(fileobj=io.BytesIO(payload)) as compressed:
            written = 0
            while True:
                chunk = compressed.read(min(1024 * 1024, MAX_DATABASE + 1 - written))
                if not chunk:
                    break
                written += len(chunk)
                if written > MAX_DATABASE:
                    raise ValueError('GeoIP database exceeds its size limit')
                output.write(chunk)
            output.flush(); os.fsync(output.fileno())
        with maxminddb.open_database(temporary) as reader:
            metadata = reader.metadata()
            if metadata.ip_version != 6 or not metadata.database_type.lower().startswith('dbip-country'):
                raise ValueError('Not a DB-IP IPv4/IPv6 Country database')
            epoch = metadata.build_epoch
            if not time.time() - 120 * 86400 <= epoch <= time.time() + 86400:
                raise ValueError('GeoIP build date is invalid or too old')
            for address in ('8.8.8.8', '2001:4860:4860::8888'):
                code = ((reader.get(address) or {}).get('country') or {}).get('iso_code', '')
                if len(code) != 2 or not code.isascii() or not code.isalpha():
                    raise ValueError('GeoIP IPv4/IPv6 sample validation failed')
        os.chmod(temporary, 0o644)
        os.utime(temporary, (epoch, epoch))  # Resolver freshness reflects the data, not a copy date.
        digest = hashlib.sha256(Path(temporary).read_bytes()).hexdigest()
        os.replace(temporary, database)
        if os.name == 'posix':
            parent = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(parent)
            finally:
                os.close(parent)
        result = {'provider': 'DB-IP Lite Country', 'month': month, 'build_epoch': epoch,
                  'updated_at': dt.datetime.now(dt.timezone.utc).isoformat(), 'size': written,
                  'sha256': digest, 'attribution': ATTRIBUTION}
        atomic_json(status, result)
        return {**result, 'downloaded': True}
    finally:
        if temporary and os.path.exists(temporary):
            os.unlink(temporary)


def main():
    print(json.dumps(update()))


if __name__ == '__main__':
    main()
