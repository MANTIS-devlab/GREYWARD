"""Bounded scan receipts: a receipt describes observed bytes, never safety."""
import hashlib
import json
import os
import stat
from pathlib import Path

MAX_TREE_ENTRIES = 4096
POLICY_GENERATION = 'scope-1'  # Bump when scan access/result semantics change.


def generation(info):
    if not info.get('engine_version') or not info.get('database_version'):
        return None
    return '|'.join((POLICY_GENERATION, str(info['engine_version']), str(info['database_version'])))


def fingerprint(path: Path) -> str | None:
    """Include ctime/inode and every child, with no aliases or unbounded walks.

    A large/inaccessible tree has unknown validity rather than a clean badge.
    The scanner can still inspect it; a later Properties view must rescan it.
    """
    digest = hashlib.sha256()
    pending = [path]
    seen = 0
    try:
        while pending:
            current = pending.pop()
            metadata = current.lstat()
            if stat.S_ISLNK(metadata.st_mode):
                return None
            if not (stat.S_ISREG(metadata.st_mode) or stat.S_ISDIR(metadata.st_mode)):
                return None
            seen += 1
            if seen > MAX_TREE_ENTRIES:
                return None
            digest.update(json.dumps((str(current.relative_to(path.parent)), metadata.st_dev,
                metadata.st_ino, metadata.st_mode, metadata.st_size,
                metadata.st_mtime_ns, metadata.st_ctime_ns)).encode('utf-8'))
            if stat.S_ISDIR(metadata.st_mode):
                with os.scandir(current) as children:
                    names = []
                    for child in children:
                        names.append(child.name)
                        if len(names) + seen > MAX_TREE_ENTRIES:
                            return None
                pending.extend(current / name for name in sorted(names, reverse=True))
        return digest.hexdigest()
    except (OSError, ValueError):
        return None


def schema(connection):
    connection.execute('''CREATE TABLE IF NOT EXISTS file_scan_receipts (
        owner_uid INTEGER NOT NULL, path TEXT NOT NULL, fingerprint TEXT,
        database_version TEXT, state TEXT NOT NULL, scanned_at TEXT NOT NULL,
        operation_id TEXT NOT NULL, PRIMARY KEY(owner_uid, path))''')


def save(store, owner_uid, path, before, after, generation, state, operation_id, timestamp, *, reason=None):
    if owner_uid is None:
        return
    if not before or before != after:
        state = 'PARTIAL'
        reason = None
    connection = store._connect()
    try:
        with connection:
            schema(connection)
            # Keep the existing seven-column layout, so an RPM rollback can
            # still read/write receipts. Older readers treat this marker as
            # incomplete/unknown, never as a clean scan.
            stored_state = 'PARTIAL_LIMIT' if reason == 'ENGINE_LIMIT' and state == 'PARTIAL' else state
            connection.execute('''INSERT OR REPLACE INTO file_scan_receipts VALUES(?,?,?,?,?,?,?)''',
                (int(owner_uid), str(path), after, generation, stored_state, timestamp, operation_id))
            connection.execute('''DELETE FROM file_scan_receipts WHERE rowid IN
                (SELECT rowid FROM file_scan_receipts ORDER BY scanned_at DESC LIMIT -1 OFFSET 8192)''')
    finally:
        connection.close()


def lookup(store, owner_uid, path, generation, definitions_current):
    connection = store._connect()
    try:
        with connection:
            schema(connection)
        row = connection.execute('SELECT * FROM file_scan_receipts WHERE owner_uid=? AND path=?',
            (int(owner_uid), str(path))).fetchone()
    finally:
        connection.close()
    if not row:
        return {'state': 'NOT_SCANNED', 'validity': 'UNKNOWN', 'detail': 'No scan recorded for this selection.'}
    value = dict(row)
    if value['state'] == 'PARTIAL_LIMIT':
        value.update(state='PARTIAL', incomplete_reason='ENGINE_LIMIT')
    value.pop('path', None)
    value.pop('owner_uid', None)
    previous = value.pop('fingerprint', None)
    current = fingerprint(path)
    valid = previous and current == previous and value['state'] in {'CLEAN', 'THREAT'}
    value['validity'] = ('UNKNOWN' if not current or not previous or value['state'] == 'PARTIAL'
        else 'CHANGED' if current != previous else 'DEFINITIONS_CHANGED'
        if not definitions_current or generation != value['database_version'] else 'VALID' if valid else 'UNKNOWN')
    value['detail'] = ('No known threats found in the recorded scan.' if value['state'] == 'CLEAN'
        else 'A known threat was detected.' if value['state'] == 'THREAT' else 'The scan did not fully complete.')
    if value['validity'] != 'VALID':
        value['detail'] += ' A new scan is required.'
    if (value.get('incomplete_reason') == 'ENGINE_LIMIT' and previous and current == previous
            and definitions_current and generation == value['database_version']):
        value['retry_policy'] = 'ON_CHANGE'
        value['detail'] = 'An engine limit prevented a complete scan. Automatic retry waits for changed content or definitions; a manual scan remains available.'
    return value
