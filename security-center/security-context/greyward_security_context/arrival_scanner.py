"""Quiet, per-user arrival scans, using the existing typed scanner boundary.

No raw ClamAV socket, policy changes, quarantine, or file mutation. Queue state
survives a session/service restart; only actual detections reach the notifier.
"""
import hashlib
import itertools
import json
import logging
import os
import sqlite3
import stat
import threading
import time
from pathlib import Path
from .scan_cache import generation as scan_generation

LOG = logging.getLogger(__name__)
PARTIAL_SUFFIXES = ('.part', '.partial', '.crdownload', '.download', '.tmp', '.swp', '~')
MAX_FILE_BYTES = 256 * 1024 * 1024
MAX_QUEUE = 8192
SETTLE_SECONDS = 8


def identity(path, uid):
    try:
        str(path).encode('utf-8', errors='strict')
        if path.name.startswith('.') or path.name.lower().endswith(PARTIAL_SUFFIXES):
            return None
        current = Path(path.anchor)
        for part in path.parts[1:]:
            current /= part
            if current.is_symlink():
                return None
        value = path.lstat()
        if value.st_uid != uid or not stat.S_ISREG(value.st_mode) or value.st_size > MAX_FILE_BYTES:
            return None
        return hashlib.sha256(str((value.st_dev, value.st_ino, value.st_size,
            value.st_mtime_ns, value.st_ctime_ns)).encode()).hexdigest()
    except (OSError, UnicodeError):
        return None


class ArrivalQueue:
    """Single-worker SQLite queue; no clean result is inferred from this cache."""
    def __init__(self, path, uid):
        self.path, self.uid = Path(path), uid
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(self.path)
        os.chmod(self.path, 0o600)
        self.connection.execute("PRAGMA journal_mode=WAL")
        self.connection.execute("PRAGMA synchronous=NORMAL")
        self.connection.execute('''CREATE TABLE IF NOT EXISTS arrivals (
            path TEXT PRIMARY KEY, signature TEXT NOT NULL, observed REAL NOT NULL,
            generation TEXT NOT NULL, done INTEGER NOT NULL DEFAULT 0,
            retry_at REAL NOT NULL DEFAULT 0, attempts INTEGER NOT NULL DEFAULT 0, priority INTEGER NOT NULL DEFAULT 0)''')
        if 'priority' not in {row[1] for row in self.connection.execute('PRAGMA table_info(arrivals)')}:
            self.connection.execute('ALTER TABLE arrivals ADD COLUMN priority INTEGER NOT NULL DEFAULT 0')
        self.connection.execute('CREATE TABLE IF NOT EXISTS inflight(operation_id TEXT PRIMARY KEY, paths TEXT NOT NULL)')
        self.connection.execute('CREATE TABLE IF NOT EXISTS watermarks(root TEXT PRIMARY KEY, observed REAL NOT NULL)')
        self.connection.execute('INSERT OR IGNORE INTO watermarks VALUES(?,?)', ('@first-start', time.time()))
        self.connection.commit()

    def since(self, root, home=False):
        row = self.connection.execute('SELECT observed FROM watermarks WHERE root=?', (str(root),)).fetchone()
        if row:
            return row[0]
        if home:
            return self.connection.execute("SELECT observed FROM watermarks WHERE root='@first-start'").fetchone()[0]
        return 0

    def walked(self, root, started):
        with self.connection:
            self.connection.execute('INSERT OR REPLACE INTO watermarks VALUES(?,?)', (str(root), started - 1))

    def definitions_changed(self, generation):
        with self.connection:
            self.connection.execute('''UPDATE arrivals SET generation=?,done=0,retry_at=0,attempts=0
                WHERE generation != ?''', (generation, generation))

    def observe(self, path, generation, now, priority=0):
        signature = identity(path, self.uid)
        if not signature:
            return True
        with self.connection:
            row = self.connection.execute('SELECT priority FROM arrivals WHERE path=?', (str(path),)).fetchone()
            # A live USB arrival deserves the same priority as a home arrival.
            # A later bulk reconciliation must not demote that pending work.
            if row is not None:
                priority = max(priority, row[0])
            if row is None or row[0] != priority:
                count = self.connection.execute('SELECT count(*) FROM arrivals WHERE priority=?', (priority,)).fetchone()[0]
                if count >= MAX_QUEUE:
                    # Keep pending work. Evict an old completed cache entry or
                    # defer the new arrival to reconciliation, without a storm.
                    removed = self.connection.execute('''DELETE FROM arrivals WHERE path IN
                        (SELECT path FROM arrivals WHERE done!=0 AND priority=? ORDER BY observed LIMIT 1)''', (priority,)).rowcount
                    if not removed:
                        return False
            self.connection.execute('''INSERT INTO arrivals(path,signature,observed,generation,priority)
                VALUES(?,?,?,?,?) ON CONFLICT(path) DO UPDATE SET signature=excluded.signature,
                observed=excluded.observed,generation=excluded.generation,priority=excluded.priority,done=0,retry_at=0,attempts=0
                WHERE arrivals.signature != excluded.signature OR arrivals.generation != excluded.generation OR arrivals.priority != excluded.priority''',
                (str(path), signature, now, generation, priority))
        return True


    def ready(self, now, roots, limit=32):
        rows = self.connection.execute('''SELECT path,signature FROM arrivals WHERE done=0
            AND observed<=? AND retry_at<=? ORDER BY priority DESC,observed LIMIT ?''',
            (now - SETTLE_SECONDS, now, limit)).fetchall()
        ready = []
        for raw, signature in rows:
            path = Path(raw)
            if not any(path.is_relative_to(root) for root in roots):
                # A removed mount is not an authorized scan root any more.
                with self.connection:
                    self.connection.execute('DELETE FROM arrivals WHERE path=?', (raw,))
                continue
            current = identity(path, self.uid)
            if current is None:
                with self.connection:
                    self.connection.execute('DELETE FROM arrivals WHERE path=?', (raw,))
            elif current != signature:
                generation, priority = self.connection.execute('SELECT generation,priority FROM arrivals WHERE path=?', (raw,)).fetchone()
                self.observe(path, generation, now, priority)
            else:
                ready.append(raw)
        return ready

    def finished(self, paths, complete, now, *, terminal=False):
        with self.connection:
            for raw in paths:
                self.connection.execute('''UPDATE arrivals SET done=?, attempts=attempts+1,
                    retry_at=? + min(1800,60 * (attempts+1)*(attempts+1)) WHERE path=?''',
                    (1 if complete else 2 if terminal else 0, now, raw))

    def pending(self):
        return self.connection.execute('SELECT count(*) FROM arrivals WHERE done=0').fetchone()[0]

    def inflight(self, operation_id=None, paths=None):
        if operation_id is not None:
            with self.connection:
                self.connection.execute('DELETE FROM inflight')
                self.connection.execute('INSERT INTO inflight VALUES(?,?)', (operation_id, json.dumps(paths)))
        row = self.connection.execute('SELECT operation_id,paths FROM inflight LIMIT 1').fetchone()
        return (row[0], json.loads(row[1])) if row else (None, [])

    def clear_inflight(self):
        with self.connection:
            self.connection.execute('DELETE FROM inflight')


class ArrivalScanner:
    def __init__(self):
        self._wake = threading.Event()
        self._roots = set()
        self._monitors = {}
        self._events = set()
        self._walks = {}
        self._lock = threading.Lock()
        self._status = {'state': 'STARTING', 'pending': 0, 'detail': 'Waiting for the arrival observer.'}

    def snapshot(self):
        with self._lock:
            return dict(self._status)

    def _state(self, state, pending=0, detail=''):
        with self._lock:
            self._status = {'state': state, 'pending': pending, 'detail': detail}

    def start(self):
        from gi.repository import GLib, Gio
        self.GLib, self.Gio = GLib, Gio
        for kind in (GLib.UserDirectory.DIRECTORY_DOWNLOAD, GLib.UserDirectory.DIRECTORY_DESKTOP):
            raw = GLib.get_user_special_dir(kind)
            if raw and Path(raw).is_dir() and Path(raw) != Path.home():
                self._roots.add(Path(raw))
        self.volumes = Gio.VolumeMonitor.get()
        self.volumes.connect('mount-added', lambda *_: self._refresh_mounts())
        self.volumes.connect('mount-removed', lambda *_: self._refresh_mounts())
        self._fixed_roots = set(self._roots)
        self._refresh_mounts()
        threading.Thread(target=self._run, name='greyward-arrival-scans', daemon=True).start()

    def _refresh_mounts(self):
        # Mounts appear only after authorization/mounting. Require UDisks'
        # physical USB bus identity as well; never walk network or system mounts.
        import dbus
        roots = set(self._fixed_roots)
        try:
            objects = dbus.Interface(dbus.SystemBus().get_object('org.freedesktop.UDisks2',
                '/org/freedesktop/UDisks2'), 'org.freedesktop.DBus.ObjectManager').GetManagedObjects(timeout=3)
            usb_devices = set()
            for interfaces in objects.values():
                block = interfaces.get('org.freedesktop.UDisks2.Block')
                if block:
                    drive = objects.get(block.get('Drive'), {}).get('org.freedesktop.UDisks2.Drive', {})
                    if drive.get('ConnectionBus') == 'usb':
                        usb_devices.add(bytes(block.get('Device', [])).rstrip(b'\0').decode())
            for mount in self.volumes.get_mounts():
                volume = mount.get_volume()
                raw = mount.get_root().get_path()
                if raw and volume and volume.get_identifier('unix-device') in usb_devices:
                    roots.add(Path(raw))
        except (dbus.DBusException, ValueError, UnicodeError):
            LOG.warning('USB scan roots could not be verified; no additional roots accepted.')
        with self._lock:
            self._roots = roots
        for path in tuple(self._monitors):
            if not any(path.is_relative_to(root) for root in roots):
                self._monitors.pop(path).cancel()
        # Install root watches immediately, even while a persisted batch is
        # finishing. Bulk traversal may not reach a newly mounted root yet.
        for root in sorted(roots):
            if root not in self._monitors and len(self._monitors) >= 512:
                child = next((path for path in self._monitors if path not in roots), None)
                if child is not None:
                    self._monitors.pop(child).cancel()
            self._watch(root)
        self._wake.set()

    def _watch(self, path):
        from gi.repository import GLib
        if path in self._monitors or len(self._monitors) >= 512 or not any(path.is_relative_to(root) for root in self._roots):
            return False
        try:
            monitor = self.Gio.File.new_for_path(str(path)).monitor_directory(self.Gio.FileMonitorFlags.WATCH_MOVES, None)
            monitor.connect('changed', self._changed)
            self._monitors[path] = monitor
        except GLib.Error:
            pass
        return False

    def _changed(self, _monitor, file, other, _event):
        with self._lock:
            for item in (file, other):
                raw = item.get_path() if item else None
                if raw and len(self._events) < 2048:
                    self._events.add(Path(raw))

    def _walk_entries(self, root):
        pending = [root]
        while pending:
            directory = pending.pop()
            self.GLib.idle_add(self._watch, directory)
            entries = []
            try:
                # Close directory descriptors before yielding or waiting for a
                # scan, so the observer cannot keep removable storage busy.
                with os.scandir(directory) as stream:
                    for seen, entry in enumerate(stream):
                        if seen >= 16384:
                            LOG.warning('Arrival scan directory limit reached; coverage remains bounded.')
                            break
                        if entry.is_symlink() or entry.name.startswith('.'):
                            continue
                        entries.append((Path(entry.path), entry.stat(follow_symlinks=False)))
                for path, metadata in entries:
                    if stat.S_ISDIR(metadata.st_mode):
                        if len(pending) < 8192:
                            pending.append(path)
                        yield None, None
                    elif stat.S_ISREG(metadata.st_mode):
                        yield path, metadata
            except OSError:
                continue

    def _walk(self, roots, queue, generation):
        for root in roots:
            if root not in self._walks:
                self._walks[root] = (time.time(), queue.since(root, root in self._fixed_roots), self._walk_entries(root))

    def _walk_step(self, roots, queue, generation):
        # Retain the iterator between bounded slices instead of rescanning the
        # beginning of a large drive forever. Each root advances independently.
        budget = 1024
        ordered = sorted(self._walks.items(), key=lambda item: (not any(item[0].is_relative_to(home) for home in self._fixed_roots), -item[1][0]))
        for root, (started, since, entries) in ordered:
            if not any(root.is_relative_to(allowed) for allowed in roots):
                self._walks.pop(root)
                getattr(entries, "close", lambda: None)()
                continue
            try:
                while budget > 0:
                    path, metadata = next(entries)
                    budget -= 1
                    if path is not None and max(metadata.st_mtime, metadata.st_ctime) >= since:
                        priority = int(any(path.is_relative_to(home) for home in self._fixed_roots))
                        if not queue.observe(path, generation, time.time(), priority):
                            # Preserve this exact cursor until capacity is free;
                            # a large USB volume must not lose deferred entries.
                            self._walks[root] = (started, since, itertools.chain([(path, metadata)], entries))
                            break
            except StopIteration:
                self._walks.pop(root)
                queue.walked(root, started)
            if budget <= 0:
                break

    def _run(self):
        while True:
            try:
                self._worker()
            except Exception:
                LOG.exception('The arrival observer stopped; no background coverage is claimed.')
                self._state('PAUSED', detail='The arrival observer will retry automatically in one minute.')
                time.sleep(60)

    def _worker(self):
        import dbus
        state = Path(os.environ.get('XDG_STATE_HOME', Path.home() / '.local/state')) / 'greyward/scan-arrivals.sqlite3'
        queue = ArrivalQueue(state, os.getuid())
        proxy = None
        active, paths = queue.inflight()
        next_walk, generation, last_warning = 0, None, 0
        def receipts(paths):
            result = json.loads(str(proxy.GetFileScanInfoBatch(json.dumps(paths), timeout=10)))
            if result.get('state') != 'AVAILABLE' or len(result.get('items', [])) != len(paths):
                raise ValueError('Scan receipt batch unavailable')
            return {item['path']: item['info'] for item in result['items']}
        while True:
            try:
                if proxy is None:
                    proxy = dbus.Interface(dbus.SystemBus(private=True).get_object(
                        'systems.mantis.greyward.ClamAvScan1', '/systems/mantis/greyward/ClamAvScan1',
                        introspect=False), 'systems.mantis.greyward.ClamAvScan1')
                with self._lock:
                    roots = set(self._roots)
                    changed = set() if active else self._events
                    if not active:
                        self._events = set()
                if active:
                    self._state('SCANNING', queue.pending(), 'Scanning a batch of stable arriving files.')
                    result = json.loads(str(proxy.GetScanStatus(active, timeout=10)))
                    if result.get('state') not in {'QUEUED', 'SCANNING', 'FINALIZING'}:
                        # A completed operation can contain detections; this
                        # queue records completion only, never file safety.
                        # A mixed batch may fail for one source. Preserve the
                        # confirmed receipts of its other files instead of
                        # repeatedly scanning every healthy file in that batch.
                        batch = receipts(paths)
                        for raw in paths:
                            receipt = batch[raw]
                            queue.finished([raw], receipt.get('validity') == 'VALID', time.time(),
                                terminal=receipt.get('retry_policy') == 'ON_CHANGE')
                        # Root detections already drive the existing DMS
                        # notification router, including across service restarts.
                        # Do not duplicate them as legacy USB scan notices.
                        queue.clear_inflight()
                        active, paths = None, []
                else:
                    info = json.loads(str(proxy.GetClamAvStatus(timeout=10)))
                    current_generation = scan_generation(info)
                    if info.get('status') == 'CURRENT' and current_generation:
                        if self._wake.is_set() or time.monotonic() >= next_walk or generation != current_generation:
                            self._wake.clear()
                            if generation != current_generation:
                                queue.definitions_changed(current_generation)
                            generation = current_generation
                            self._walk(roots, queue, generation)
                            next_walk = time.monotonic() + 600
                        # Reconciliation and live events are complementary:
                        # never discard arrivals when a periodic walk starts.
                        for path in changed:
                            if any(path.is_relative_to(root) for root in roots):
                                if path.is_dir() and not path.is_symlink():
                                    self._walk({path}, queue, generation)
                                else:
                                    queue.observe(path, generation, time.time(), priority=1)
                        self._walk_step(roots, queue, generation)
                        paths = []
                        ready = queue.ready(time.time(), roots)
                        batch = receipts(ready) if ready else {}
                        for raw in ready:
                            receipt = batch[raw]
                            if receipt.get('validity') == 'VALID':
                                queue.finished([raw], True, time.time())
                            elif receipt.get('retry_policy') == 'ON_CHANGE':
                                queue.finished([raw], False, time.time(), terminal=True)
                            else:
                                paths.append(raw)
                        if paths:
                            result = json.loads(str(proxy.StartScan(json.dumps({'mode': 'FILE', 'paths': paths, 'background': True}), timeout=10)))
                            active = result.get('operation_id')
                            if active:
                                queue.inflight(active, paths)
                            if not active:
                                queue.finished(paths, False, time.time())
                        pending = queue.pending()
                        self._state('SCANNING' if active else 'WATCHING', pending,
                            'Observing Downloads, Desktop and verified mounted USB storage, within scan limits.')
                    else:
                        self._state('PAUSED', detail='Arrival scanning is waiting for current definitions and the scanner.')
            except (dbus.DBusException, OSError, ValueError, sqlite3.Error):
                proxy = None
                self._state('PAUSED', detail='Scanner unavailable; the persistent queue will retry.')
                if time.monotonic() - last_warning >= 300:
                    last_warning = time.monotonic()
                    LOG.warning('Arrival scanning paused; the next bounded retry will resume its durable queue.')
            # Coalesce bursts, avoid repeatedly loading definitions per file.
            time.sleep(10 if active else 15)
