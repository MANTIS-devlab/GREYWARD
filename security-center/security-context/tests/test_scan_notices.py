import datetime as dt
import json
import unittest
from greyward_security_context.scan_notices import results, appearance

class ScanNoticeTests(unittest.TestCase):
 def scan(self,**kwargs):
  value={'operation_id':'scan-fixture','state':'COMPLETED','ended_at':dt.datetime.now(dt.timezone.utc).isoformat(),'detection_count':0,'files_inspected':4,'error_count':0,'skipped_count':0,'scope':{'label':'A folder','background':False}}
  value.update(kwargs);return value
 def render(self,scan,**kwargs):return results({'state':'AVAILABLE','latest_scan':scan,**kwargs})
 def test_one_manual_result_with_readable_native_style(self):
  scan=self.scan();items=self.render(scan,recent_scans=[scan,scan]);self.assertEqual(len(items),1)
  self.assertEqual(items[0]['scan_status'],'CLEAN');self.assertEqual(items[0]['notification_title'],'A folder');self.assertEqual(items[0]['scan_caption'],'4 files checked')
  body,image=appearance(items[0]);self.assertIn('size="5"',body);self.assertIn('#A7D8B7',body);self.assertTrue(image.endswith('clean.svg?design=2'))
  self.assertEqual(items[0]['actions'],[{'id':'open','label':'View scan'}])
 def test_background_success_and_any_detection_count_never_get_completion_toast(self):
  self.assertEqual(self.render(self.scan(scope={'background':True})),[])
  self.assertEqual(self.render(self.scan(detection_count=1)),[])
  self.assertEqual(self.render(self.scan(detection_count=None)),[])
 def test_errors_skips_interruption_and_cancellation_are_not_clean(self):
  for fields,status in [({'error_count':1},'PARTIAL'),({'skipped_count':2},'PARTIAL'),({'state':'INTERRUPTED'},'FAILED'),({'state':'FAILED'},'FAILED'),({'state':'CANCELLED'},'CANCELLED'),({'files_inspected':0},'EMPTY'),({'files_inspected':None},'PARTIAL'),({'error_count':None},'PARTIAL')]:
   with self.subTest(fields=fields):
    value=self.render(self.scan(**fields))[0];self.assertEqual(value['scan_status'],status);self.assertNotIn('No threats detected',appearance(value)[0])
 def test_age_provider_failure_and_unfinished_operations_never_claim_success(self):
  self.assertEqual(self.render(self.scan(ended_at='2000-01-01T00:00:00Z')),[])
  self.assertEqual(self.render(self.scan(state='SCANNING')),[])
  self.assertEqual(results({'state':'UNAVAILABLE','latest_scan':self.scan()}),[])
 def test_filename_cannot_change_markup_or_add_lines(self):
  item=self.render(self.scan(scope={'label':'file<b>RED</b>\n\u202e.png'}))[0]
  item['scan_caption'] = '<b>filename-controlled text</b>'
  body,image=appearance(item);self.assertNotIn('<b>filename-controlled text</b>',body);self.assertIn('&lt;b&gt;',body);self.assertNotIn('<b>RED</b>',body);self.assertNotIn('\u202e',body);self.assertNotIn('\n',body)
  self.assertTrue(image.startswith('file:///usr/share/greyward-security-center/'))
  self.assertIsNone(appearance({'kind':'scan-result','scan_status':'../../private'}))
 def test_recent_manual_completion_survives_newer_background_result(self):
  manual=self.scan();background=self.scan(operation_id='background',scope={'background':True})
  items=self.render(background,recent_scans=[background,manual]);self.assertEqual(len(items),1);self.assertEqual(items[0]['id'],'scan-result:scan-fixture')
