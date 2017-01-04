# -*- coding: utf-8 -*-
"""
test.test_backend_plaintext
===========================

Tests the plaintext backend.

:author: Joe Strickler <joe@decafjoe.com>
:copyright: Joe Strickler, 2016-2017. All rights reserved.
:license: Proprietary
"""
import os
import shutil
import tempfile
import unittest

from safe import PlaintextSafeBackend


class PlaintextSafeBackendTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def test_read(self):
        path = os.path.join(self.tmp, 'test.json')
        with open(path, 'w') as f:
            f.write('1')
        self.assertEqual(1, PlaintextSafeBackend().read(path))

    def test_write(self):
        path = os.path.join(self.tmp, 'test.json')
        PlaintextSafeBackend().write(path, 1)
        with open(path) as f:
            self.assertEqual('1', f.read())
