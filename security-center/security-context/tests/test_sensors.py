import unittest
from greyward_security_context.sensors import PipeWireMonitor, observe, observe_activity


def graph(kind='Audio', app='OBS', link='active', node='running', source=None):
    return [
        {'id': 7, 'type': 'PipeWire:Interface:Client', 'info': {'props': {'application.name': app}}},
        {'id': 3, 'type': 'PipeWire:Interface:Node', 'info': {'props': {'media.class': source or kind + '/Source'}}},
        {'id': 9, 'type': 'PipeWire:Interface:Node', 'info': {'state': node, 'props': {'media.class': 'Stream/Input/' + kind, 'client.id': 7}}},
        {'id': 10, 'type': 'PipeWire:Interface:Link', 'info': {'state': link, 'output-node-id': 3, 'input-node-id': 9}},
    ]


class SensorTests(unittest.TestCase):
    def test_linked_native_microphone_is_attributed(self):
        self.assertEqual(observe(graph()), [{'kind': 'MICROPHONE', 'application': 'OBS', 'attribution': 'RELIABLE'}])

    def test_portal_camera_is_not_attributed(self):
        self.assertEqual(observe(graph('Video', 'xdg-desktop-portal')), [{'kind': 'CAMERA', 'application': None, 'attribution': 'AMBIGUOUS'}])

    def test_inactive_or_error_graph_is_not_capture(self):
        for state in ['paused', 'error', 'init', 'negotiating', None]:
            self.assertEqual(observe(graph(link=state)), [])
        self.assertEqual(observe(graph(node='suspended')), [])
        self.assertEqual(observe(graph()[:-1]), [])

    def test_playback_monitor_is_not_microphone(self):
        self.assertEqual(observe(graph(source='Audio/Sink')), [])
        value = graph()
        value[2]['info']['props']['stream.capture.sink'] = True
        self.assertEqual(observe(value), [])

    def test_duplicate_channel_links_do_not_duplicate_activity(self):
        value = graph()
        value.append(value[-1].copy())
        self.assertEqual(len(observe(value)), 1)

    def test_screen_cast_is_distinct_from_camera_capture(self):
        value = graph('Video', 'Browser')
        value[2]['info']['props']['media.role'] = 'Screen'
        activity = observe_activity(value)
        self.assertEqual(activity['sensors'], [])
        self.assertEqual(activity['screen_shares'], [{'application': 'Browser', 'attribution': 'RELIABLE'}])

    def test_unmarked_video_capture_remains_camera_activity(self):
        activity = observe_activity(graph('Video', 'Camera App'))
        self.assertEqual(activity['screen_shares'], [])
        self.assertEqual(activity['sensors'], [{'kind': 'CAMERA', 'application': 'Camera App', 'attribution': 'RELIABLE'}])

    def test_monitor_updates_the_snapshot_without_a_one_shot_graph_probe(self):
        monitor = PipeWireMonitor()
        monitor._apply(graph())
        activity, error, observed_at = monitor.snapshot()
        self.assertIsNone(error)
        self.assertIsNotNone(observed_at)
        self.assertEqual(activity['sensors'][0]['kind'], 'MICROPHONE')
