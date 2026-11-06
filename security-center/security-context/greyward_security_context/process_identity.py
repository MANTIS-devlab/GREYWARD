"""Read-only kernel process-instance identity. Never reads arguments or memory."""
import base64
import datetime as dt
import hashlib
import os
from pathlib import Path
import select
import time


def event_time(value):
    try:
        parsed=dt.datetime.fromisoformat(str(value).replace('Z','+00:00'))
        # OpenSnitch statistics use daemon-local wall time without an offset.
        return parsed.astimezone(dt.timezone.utc).timestamp()
    except (TypeError,ValueError,OverflowError):return None


def instance_key(pid, *, occurred_at=None, exec_id=None, expected_uid=None):
    """PID + boot + kernel birth ticks; an exited/reused PID never gets guessed."""
    handle=None
    try:
        if isinstance(pid,bool) or not isinstance(pid,int) or pid<2:return None
        handle=os.pidfd_open(pid)
        proc=Path('/proc')/str(pid)
        start=proc.joinpath('stat').read_text().rsplit(')',1)[1].split()[19]
        if expected_uid is not None:
            uids=proc.joinpath('status').read_text().split('Uid:',1)[1].splitlines()[0].split()
            if int(expected_uid) not in map(int,uids[:2]):return None
        ticks=os.sysconf('SC_CLK_TCK')
        if exec_id:
            fields=base64.b64decode(exec_id,validate=True).decode().rsplit(':',2)
            if len(fields)!=3 or int(fields[2])!=pid or int(fields[1])<int(start)*1000000000//ticks:return None
        elif occurred_at:
            when=event_time(occurred_at)
            born=time.time()-time.clock_gettime(time.CLOCK_BOOTTIME)+int(start)/ticks
            if when is None or born>when or when>time.time()+2:return None
        else:return None
        if proc.joinpath('stat').read_text().rsplit(')',1)[1].split()[19]!=start or select.select([handle],[],[],0)[0]:return None
        boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip()
        return hashlib.sha256(f'{boot}|{pid}|{start}'.encode()).hexdigest()[:40]
    except (OSError,ValueError,TypeError,IndexError,KeyError,UnicodeError):return None
    finally:
        if handle is not None:os.close(handle)
