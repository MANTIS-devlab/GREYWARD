#!/usr/bin/python3
"""Generate selected desktop persistence probes; preserve administrator edits."""
import hashlib,json,pwd,sys
from pathlib import Path
directory=Path(sys.argv[1] if len(sys.argv)>1 else '/etc/greyward/intelligence/policies')
directory.mkdir(parents=True,exist_ok=True)
paths=['/etc/cron','/etc/systemd/system/']+[p.pw_dir+s for p in pwd.getpwall() if 1000<=p.pw_uid<65534 and p.pw_dir.startswith('/home/') for s in ('/.config/autostart/','/.config/systemd/user/')]
base={'apiVersion':'cilium.io/v1alpha1','kind':'TracingPolicy'}
definitions={
 'persistence':{**base,'metadata':{'name':'greyward-persistence'},'spec':{'kprobes':[{'call':'security_file_permission','syscall':False,'args':[{'index':0,'type':'file'},{'index':1,'type':'int'}],'selectors':[{'matchArgs':[{'index':0,'operator':'Prefix','values':paths},{'index':1,'operator':'Equal','values':['2']}]}]}]}},
 'outbound':{**base,'metadata':{'name':'greyward-outbound'},'spec':{'kprobes':[{'call':'security_socket_connect','syscall':False,'args':[{'index':1,'type':'sockaddr'}],'selectors':[{'matchArgs':[{'index':1,'operator':'Family','values':['AF_INET','AF_INET6']}]}]}]}}
}
# Tetragon parses every regular file in its policy directory, not only YAML.
# Keep bookkeeping and temporary files outside that directory.
receipt=directory.parent/('.'+directory.name+'-generated.json')
previous=json.loads(receipt.read_text()) if receipt.exists() else {}
current={}
for name,value in definitions.items():
 p=directory/(name+'.yaml')
 if not p.exists() or hashlib.sha256(p.read_bytes()).hexdigest()==previous.get(name):
  content=json.dumps(value,indent=2).encode()
  temporary=directory.parent/('.'+directory.name+'-'+name+'.tmp')
  with temporary.open('wb') as output:output.write(content)
  temporary.chmod(0o600)
  temporary.replace(p)
  p.chmod(0o600)
  current[name]=hashlib.sha256(content).hexdigest()
 # Untracked or administrator-modified policies are never overwritten.
receipt.write_text(json.dumps(current,sort_keys=True)+'\n')
receipt.chmod(0o600)
