import unittest
from decimal import Decimal
from service import authorized

class ConsentCollectorTests(unittest.TestCase):
    def test_checks_scope_and_time(self):
        grant = {'sources': ['ledger'], 'categories': ['invoice'], 'starts_at': '2026-01-01T00:00:00'}
        self.assertTrue(authorized(grant, 'ledger', 'invoice', '2026-11-11T00:00:00'))
        self.assertFalse(authorized(grant, 'ledger', 'profile', '2026-11-11T00:00:00'))


if __name__ == '__main__':
    unittest.main()
