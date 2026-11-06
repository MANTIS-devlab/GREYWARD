"""A fixed DRM rescan must not become a monitor/power/USB policy manager."""
import os
from pathlib import Path
import runpy
import tempfile
import unittest
from unittest.mock import Mock

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'environment/session/greyward-display-reprobe'
MODULE = runpy.run_path(str(SCRIPT))

@unittest.skipUnless(os.name == 'posix' and os.geteuid() == 0, 'Native root-owned sysfs fixture')
class DisplayProbeTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
  self.sys=Path(self.tmp.name)/'sys';self.drm=self.sys/'class/drm';self.drm.mkdir(parents=True)
 def card(self,name='card0',driver='nouveau',vendor='0x10de'):
  c=self.drm/name;(c/'device').mkdir(parents=True)
  d=self.sys/'bus/pci/drivers'/driver;d.mkdir(parents=True,exist_ok=True)
  (c/'device/driver').symlink_to(d);(c/'device/vendor').write_text(vendor);return c
 def connector(self,name,status='disconnected'):
  c=self.drm/name;c.mkdir();p=c/'status';p.write_text(status+'\n');p.chmod(0o644);return p
 def test_only_nouveau_external_connectors_are_eligible(self):
  self.card();external=self.connector('card0-DP-2');self.connector('card0-eDP-1')
  self.card('card1','amdgpu','0x1002');self.connector('card1-HDMI-A-1')
  self.assertEqual(MODULE['connectors'](self.sys),[external])
 def test_probe_only_writes_literal_detect_and_never_connected_outputs(self):
  p=self.connector('card0-DP-2','connected')
  self.assertFalse(MODULE['detect'](p));self.assertEqual(p.read_text(),'connected\n')
  p.write_text('disconnected\n');self.assertTrue(MODULE['detect'](p));self.assertEqual(p.read_text(),'detect\n')
 def test_burst_is_bounded_and_preserves_existing_outputs(self):
  self.card();missing=self.connector('card0-DP-2');present=self.connector('card0-HDMI-A-1','connected')
  sleeps=[];writes=[]
  def probe(p):
   if p.read_text().strip()!='disconnected':return False
   writes.append(p);p.write_text('connected\n');return True
  self.assertEqual(MODULE['recover'](self.sys,sleeps.append,probe),1)
  self.assertEqual(writes,[missing]);self.assertEqual(present.read_text(),'connected\n');self.assertEqual(sleeps,[1.0,1.0,2.0])
 def test_no_gpu_has_no_sleep_or_side_effect(self):
  pause=Mock();probe=Mock();self.assertEqual(MODULE['recover'](self.sys,pause,probe),0);pause.assert_not_called();probe.assert_not_called()
 def test_unplug_during_probe_does_not_fail_the_job(self):
  self.card();p=self.connector('card0-DP-2');calls=[]
  def probe(path):calls.append(path);raise FileNotFoundError(2,'Device disappeared')
  self.assertEqual(MODULE['recover'](self.sys,lambda _:None,probe),0);self.assertEqual(len(calls),3)
 def test_missing_display_cannot_trigger_an_unbounded_retry(self):
  self.card();p=self.connector('card0-DP-2');probe=Mock(return_value=True)
  self.assertEqual(MODULE['recover'](self.sys,lambda _:None,probe),3);self.assertEqual(probe.call_count,3)
 def test_foreign_symlink_and_writable_sysfs_fixture_are_rejected(self):
  self.card();p=self.connector('card0-DP-2');p.chmod(0o666);self.assertEqual(MODULE['connectors'](self.sys),[])
  p.unlink();outside=Path(self.tmp.name)/'status';outside.write_text('disconnected');p.symlink_to(outside)
  self.assertEqual(MODULE['connectors'](self.sys),[])

class DisplayProbeContracts(unittest.TestCase):
 def test_event_driven_root_job_without_polling_or_new_auth_interface(self):
  rule=(ROOT/'environment/session/70-greyward-display-reprobe.rules').read_text()
  service=(ROOT/'environment/session/greyward-display-reprobe.service').read_text()
  self.assertIn('usb_interface',rule);self.assertIn('bInterfaceClass}=="09"',rule);self.assertIn('SYSTEMD_WANTS',rule);self.assertNotIn('RUN+=',rule)
  self.assertIn('/usr/bin/python3 -I ',service);self.assertIn('CapabilityBoundingSet=\n',service)
  self.assertIn('TimeoutStartSec=15',service);self.assertNotIn('Restart=',service)
  script=SCRIPT.read_text();self.assertNotIn('subprocess',script);self.assertNotIn('argparse',script)
  self.assertIn("status.write_text('detect\\n')",script)

if __name__=='__main__':unittest.main()
