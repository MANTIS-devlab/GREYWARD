#!/usr/bin/python3
"""Fixed sensor-start attachment receipt; runs inside the sensor's capability set."""
import json,os,sys,time
from pathlib import Path
root=Path('/sys/fs/bpf/greyward-intelligence')
target=Path('/var/lib/greyward/intelligence/sensor/attachment.json')
pid=int(sys.argv[1]);links={}
for _ in range(40):
    links={name:(root/('greyward-'+name)/'generic_kprobe/multi_kprobe/link').is_file() for name in ('persistence','outbound')}
    if all(links.values()):break
    time.sleep(.5)
value={'pid':pid,'boot':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'links':links}
temporary=target.with_suffix('.tmp');temporary.write_text(json.dumps(value));temporary.chmod(0o600);os.replace(temporary,target)
