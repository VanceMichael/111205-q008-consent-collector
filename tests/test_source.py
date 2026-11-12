import unittest
from synthetic_source import SyntheticSource


class SourceTests(unittest.TestCase):
    def test_sessions_and_cursors_are_bound_to_a_source_instance(self):
        first = SyntheticSource(1)
        second = SyntheticSource(2)
        session = first.request('POST', '/session')['json']['session']
        self.assertEqual(second.request('GET', '/items', {'X-Session': session})['status'], 403)
        headers = {'X-Session': session}
        page = first.request('GET', '/items', headers)['json']
        self.assertEqual(first.request('GET', '/items?cursor=wrong', headers)['status'], 409)
        final = first.request('GET', '/items?cursor=' + page['next'], headers)
        self.assertIsNone(final['json']['next'])
