# -*- coding: utf-8 -*-
"""
test.test_backend
=================

Tests the safe backend decorator and base class.

:copyright: (c) 2015 Joe Strickler
:license: BSD, see LICENSE for more details
"""
import unittest

import safe
from safe import backend, get_supported_backend_names, \
    BackendNameConflictError, PlaintextSafeBackend, SafeBackend

from test import backend as temporary_backend


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
        self.assertRaises(BackendNameConflictError, backend, 'test')


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
        self.assertRaises(NotImplementedError, SafeBackend.supports_platform)
        self.assertRaises(NotImplementedError, safe.write, None, None)
        safe.add_arguments()

    def test_not_supported(self):
        @backend('test')
        class TestSafeBackend(SafeBackend):
            @staticmethod
            def supports_platform():
                return False

        try:
            with temporary_backend('test'):
                self.assertEqual([], get_supported_backend_names())
        finally:
            del safe.backend_map['test']

    def test_registered_repr(self):
        expected = u'<PlaintextSafeBackend (plaintext)>'
        self.assert_string(expected, PlaintextSafeBackend())

    def test_unregistered_repr(self):
        self.assert_string(u'<SafeBackend>', SafeBackend())
