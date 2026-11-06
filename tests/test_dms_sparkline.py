"""Closed renderer repair and explicit native, isolated GPU-path regression."""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import tempfile
import time
import unittest

ROOT=Path(__file__).resolve().parents[1]
def load(name,path):
 spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
repair=load('sparkline_repair',ROOT/'packaging/greyward-dms/build-sparkline-repair.py')

class SparklineRepair(unittest.TestCase):
 def test_exact_preimage_patch_changes_only_renderer_and_antialiasing(self):
  patch=(ROOT/'environment/patches/dms-2.0/greyward-sparkline-renderer.patch').read_text()
  changed=[line for line in patch.splitlines() if line.startswith(('+','-')) and not line.startswith(('+++','---'))]
  self.assertEqual(changed,['-'+repair.OLD]+['+'+line for line in repair.NEW.splitlines()])
  m=json.loads((ROOT/'environment/production/dms-2.0-candidate.json').read_text())
  self.assertEqual(m['patches'][-1]['sha256'],repair.assemble.sha(ROOT/m['patchDirectory']/m['patches'][-1]['file']))
  self.assertTrue(m['build']['sparklineRepair']['requiresProtectedMigration'])
  self.assertNotEqual(m['releaseId'],m['build']['sparklineRepair']['baseReleaseId'])
 def test_protected_authentication_explicitly_accepts_the_new_generation(self):
  auth=load('sparkline_auth',ROOT/'security-center/packaging/application-security/authentication/assemble.py')
  m=json.loads((ROOT/'environment/production/dms-2.0-candidate.json').read_text())
  self.assertIn(m['releaseId'],auth.CANDIDATE_RELEASES)
  self.assertNotIn('v2.0.0-999',auth.CANDIDATE_RELEASES)
 def test_no_unrelated_path_or_privilege_change_in_patch(self):
  patch=(ROOT/'environment/patches/dms-2.0/greyward-sparkline-renderer.patch').read_text()
  self.assertEqual(patch.count('--- a/quickshell/dms/'),1)
  self.assertIn('--- a/quickshell/dms/'+repair.NAME,patch)
  self.assertNotIn('Qt.quit',patch)

 @unittest.skipUnless(os.environ.get('GREYWARD_SPARKLINE_NATIVE')=='1','Explicit Linux private-display native check')
 def test_packaged_chart_and_exact_crashing_path_render_with_gpu_backend(self):
  shell=Path(os.environ['GREYWARD_SPARKLINE_SHELL']).resolve()
  output=Path(os.environ['GREYWARD_SPARKLINE_OUTPUT']).resolve();output.mkdir(parents=True,exist_ok=True)
  # The /run pathname is intentionally short enough for Unix sockets. All
  # persistent inputs, captures, caches and logs stay under the task output.
  with tempfile.TemporaryDirectory(prefix='gw-sparkline-',dir='/run') as run:
   runtime=Path(run);tree=output/'shell';shutil.copytree(shell,tree)
   lab=output/'labwc';lab.mkdir();(lab/'rc.xml').write_text('<labwc_config/>');(lab/'autostart').write_text('')
   path=(ROOT/'tests/fixtures/dms-sparkline-triangulation.svgpath').read_text().strip()
   qml="""import QtQuick
import QtQuick.Shapes
import Quickshell
import qs.DCommon.Widgets as DC
ShellRoot {
 id: root
 property int ticks: 0
 FloatingWindow { id: window; implicitWidth:680; implicitHeight:180; visible:true; color:'#101316'
  Item {id:canvas;anchors.fill:parent
  DC.DSparkline { id: chart; x:20;y:20;width:299;height:43.2;maximum:100;values:[15,15,0,100,0,100,4,4,4,60,0,0];lineColor:'#a9d5bb' }
  Shape { id:exact;x:350;y:20;width:299;height:43.2
   preferredRendererType: chart.children[0].preferredRendererType
   layer.enabled:true;layer.samples:4
   ShapePath { strokeWidth:0;strokeColor:'transparent';fillColor:'#1ae1e7ed';PathSvg {path:@@PATH@@} }
   onRendererTypeChanged: if(rendererType===Shape.GeometryRenderer)console.info('GEOMETRY_CONFIRMED')
  }
  }
 }
 Timer { interval:8;running:true;repeat:true;onTriggered: {
  root.ticks++;
  chart.width=299+(root.ticks%7);
  chart.values=Array.from({length:42},(_,i)=>(i*37+root.ticks*11)%101);
  if(root.ticks===240) {stop();if(exact.rendererType!==Shape.GeometryRenderer)Qt.exit(6);else console.info('GEOMETRY_CONFIRMED');canvas.grabToImage(function(img){if(img.saveToFile(@@IMAGE@@)) {console.info('SPARKLINE_NATIVE_PASS');Qt.quit();}else Qt.exit(4);});}
 } }
 Timer {interval:12000;running:true;onTriggered:Qt.exit(8)}
}
""".replace('@@PATH@@',json.dumps(path)).replace('@@IMAGE@@',json.dumps(str(output/'sparkline.png')))
   (tree/'sparkline-test.qml').write_text(qml)
   env={**os.environ,'HOME':str(output/'home'),'XDG_RUNTIME_DIR':str(runtime),'XDG_CONFIG_HOME':str(output/'config'),'XDG_CACHE_HOME':str(output/'cache'),'XDG_STATE_HOME':str(output/'state'),'TMPDIR':str(output),'QT_QPA_PLATFORM':'wayland','WAYLAND_DISPLAY':'wayland-0','QT_QUICK_BACKEND':'rhi','QSG_RHI_BACKEND':'opengl','QSG_RENDER_LOOP':'basic','WLR_BACKENDS':'headless','WLR_HEADLESS_OUTPUTS':'1','WLR_RENDERER':'pixman','LIBGL_ALWAYS_SOFTWARE':'1','DBUS_SESSION_BUS_ADDRESS':'unix:path=/nonexistent','DBUS_SYSTEM_BUS_ADDRESS':'unix:path=/nonexistent','DMS_DISABLE_POLKIT':'1'}
   with (output/'compositor.log').open('w') as log:
    display=subprocess.Popen(['unshare','-n','labwc','-C',str(lab)],env=env,stdout=log,stderr=log,start_new_session=True)
    try:
     deadline=time.monotonic()+5
     while not (runtime/'wayland-0').exists() and time.monotonic()<deadline:
      if display.poll() is not None:break
      time.sleep(.05)
     self.assertTrue((runtime/'wayland-0').exists(),'Private compositor unavailable')
     result=subprocess.run(['unshare','-n','quickshell','-p',str(tree/'sparkline-test.qml'),'--no-color'],env=env,capture_output=True,text=True,timeout=17)
     (output/'render.log').write_text(result.stdout+result.stderr)
     self.assertEqual(result.returncode,0,result.stdout+result.stderr)
     self.assertIn('GEOMETRY_CONFIRMED',result.stdout+result.stderr)
     self.assertIn('SPARKLINE_NATIVE_PASS',result.stdout+result.stderr)
     self.assertTrue((output/'sparkline.png').stat().st_size>500)
    finally:
     if display.poll() is None:
      os.killpg(display.pid,signal.SIGTERM)
      try:display.wait(timeout=3)
      except subprocess.TimeoutExpired:os.killpg(display.pid,signal.SIGKILL);display.wait()

if __name__=='__main__':unittest.main()
