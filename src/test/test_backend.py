"""
test.test_backend
=================

Tests the safe backend decorator and base class.

:copyright: (c) 2015 Joe Strickler
:license: BSD, see LICENSE for more details
"""
import unittest

import safe
from safe import backend, PlaintextSafeBackend, SafeBackend, SafeError


class BackendDecoratorTest(unittest.TestCase):
    def setUp(self):  # noqa
        self.original_backend_map = safe.backend_map
        safe.backend_map = dict()

    def tearDown(self):  # noqa
        safe.backend_map = self.original_backend_map

    def test(self):
        class TestSafeBackend(SafeBackend):
            pass

        cls = backend('test')(TestSafeBackend)
        self.assertIs(TestSafeBackend, cls)
        self.assertIn('test', safe.backend_map)
        self.assertIs(TestSafeBackend, safe.backend_map['test'])
        self.assertRaises(SafeError, backend, 'test')


class SafeBackendTest(unittest.TestCase):
    def assert_string(self, expected, safe):
        self.assertEqual(expected, repr(safe))
        self.assertEqual(expected, str(safe))
        self.assertEqual(expected, unicode(safe))

    def test_constructor(self):
        safe = SafeBackend()
        self.assertIsNone(safe.password)
        safe = SafeBackend('foo')
        self.assertEqual('foo', safe.password)

    def test_not_implemented(self):
        safe = SafeBackend()
        self.assertRaises(NotImplementedError, safe.read, None)
        self.assertRaises(NotImplementedError, safe.write, None, None)
        safe.add_arguments()

    def test_registered_repr(self):
        expected = u'<PlaintextSafeBackend (plaintext)>'
        self.assert_string(expected, PlaintextSafeBackend())

    def test_unregistered_repr(self):
        self.assert_string(u'<SafeBackend>', SafeBackend())
