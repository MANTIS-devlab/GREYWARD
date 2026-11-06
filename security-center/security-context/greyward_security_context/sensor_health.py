"""Bounded execution/export round-trip probes, independent of risk scoring."""
from collections import OrderedDict

class ProbeTracker:
    def __init__(self):
        self.pending = OrderedDict()
        self.verified_at = None
        self.latency = None
        self.matches = 0
        self.sent = 0

    def issue(self, pid, now):
        self.pending[pid] = now
        self.sent += 1
        while self.pending and (len(self.pending) > 8 or now-next(iter(self.pending.values())) > 60):
            self.pending.popitem(last=False)

    def observe(self, raw, now):
        process = (raw.get('process_exec') or {}).get('process') or {}
        pid = process.get('pid')
        if pid not in self.pending or process.get('uid') != 0 or process.get('binary') != '/usr/bin/true':
            return False
        sent = self.pending[pid]
        # A retained record for a reused PID is not a fresh probe response.
        from .process_identity import event_time
        import time
        observed = event_time(raw.get('time'))
        if observed is None or abs((time.time()-now+sent)-observed) > 5:
            return False
        self.pending.pop(pid)
        self.verified_at = now
        self.latency = max(0, now-sent)
        self.matches += 1
        return True

    def status(self, now):
        fresh = self.verified_at is not None and now-self.verified_at <= 40
        return {'probe_state': 'VERIFIED' if fresh else 'PENDING' if self.sent < 2 else 'MISSING',
                'probe_matches': self.matches, 'probe_sent': self.sent,
                'probe_latency_seconds': round(self.latency, 3) if self.latency is not None else None}
