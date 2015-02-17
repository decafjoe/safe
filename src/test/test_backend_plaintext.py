"""
test.test_backend_plaintext
===========================

Tests the plaintext backend.

:copyright: (c) 2015 Joe Strickler
:license: BSD, see LICENSE for more details
"""
from os.path import join
from shutil import rmtree
from tempfile import mkdtemp
from unittest import TestCase

from safe import PlaintextSafeBackend


class PlaintextSafeBackendTest(TestCase):
    def setUp(self):  # noqa
        self.tmp = mkdtemp()

    def tearDown(self):  # noqa
        rmtree(self.tmp)

    def test_read(self):
        path = join(self.tmp, 'test.json')
        with open(path, 'w') as f:
            f.write('1')
        self.assertEqual(1, PlaintextSafeBackend().read(path))

    def test_write(self):
        path = join(self.tmp, 'test.json')
        PlaintextSafeBackend().write(path, 1)
        with open(path) as f:
            self.assertEqual('1', f.read())
