"""
test.test_backend_nacl
======================

Test the PyNaCl backend.

:copyright: (c) 2015 Joe Strickler
:license: BSD, see LICENSE for more details
"""
import argparse
import base64
import os
import shutil
import tempfile
import unittest

import clik
import mock

from safe import load_json, NaClSafeBackend


DATA = '{"nonce": "000000000000000000000000", "salt": "02fdfa092fb632002aeec' \
       '3d390ab0d92839f37aaace3a9da3c05fc4ce80bae0d", "data": "7C8PvMa3hLAgR' \
       '5ZpmHJEwSA=", "iterations": 1}'
KEY = 'GydVZHPphdRizVEZeppGx2AJVJ6sZHTyBsTuCET2g4k='
NONCE = 'aWlu6VW2K3PNYr2odfxz1oIZ4ANregs3'
PLAINTEXT = 'vgdfxTyB8tXPFBMW6+sMe1IoxSpMYsvUS2aEm2QkT/zl7LqvM711GhrHKNRebGE' \
            'pbNw8ASM1YfQdtmzOMUrbMQ476CUMRvBtzuo6f6E0gFfi9lVq1rExigJKg48hrx' \
            '/eBIl360j1n/1JJMocYJAuUvCgibx2iXBA4IL5N3Y4SGReBwU='
CIPHERTEXT = '8//HcD+UAOUqfftLPTMF2Y6ZO59IaBJzwpZQujL8ds5IMy6nFk2WpEdvuMUxoR' \
             'hqwN/BfJjc6HtNp/AR7EjJcnHSwg+bko/iJw1vuGPVFzi0ju7jFKfMirkyFkVI' \
             '5SaukCJDaFF6z+q9a7NzK8Dp2pmDK2HKAbbeViRKnojV+bN5c/YipD0UplmbH2' \
             'VMtFp041Wl'


class NaClSafeBackendTest(unittest.TestCase):
    def context(self, iterations=1, salt=32):
        return clik.context(args=argparse.Namespace(
            nacl_pbkdf2_iterations=iterations,
            nacl_pbkdf2_salt_length=salt,
        ))

    def test_decrypt(self):
        safe = NaClSafeBackend()
        nonce = base64.b64decode(NONCE)
        plaintext = base64.b64decode(PLAINTEXT)
        self.assertEqual(plaintext, safe.decrypt(CIPHERTEXT, KEY, nonce))

    def test_encrypt(self):
        safe = NaClSafeBackend()
        data = base64.b64decode(PLAINTEXT)
        nonce = base64.b64decode(NONCE)
        self.assertEqual(CIPHERTEXT, safe.encrypt(data, KEY, nonce))

    @mock.patch('getpass.getpass', side_effect=['foo'])
    def test_read(self, _):
        tmp = tempfile.mkdtemp()
        try:
            path = os.path.join(tmp, 'test')
            with open(path, 'w') as f:
                f.write(DATA)
            safe = NaClSafeBackend()
            safe.password = 'bar'
            with self.context():
                self.assertEqual(1, safe.read(path))
        finally:
            shutil.rmtree(tmp)

    @mock.patch('getpass.getpass', side_effect=('foo', 'foo'))
    def test_write(self, getpass):
        tmp = tempfile.mkdtemp()
        try:
            path = os.path.join(tmp, 'test')
            safe = NaClSafeBackend()
            expected_keys = ('data', 'iterations', 'salt')

            with self.context(1, 32):
                safe.write(path, 1)
            self.assertEqual(2, getpass.call_count)
            with open(path) as f:
                metadata = load_json(f)
            self.assertItemsEqual(expected_keys, metadata.keys())
            self.assertNotEqual(1, metadata['data'])
            self.assertEqual(1, metadata['iterations'])
            self.assertEqual(64, len(metadata['salt']))

            with self.context(2, 64):
                safe.write(path, 1)
            with open(path) as f:
                metadata = load_json(f)
            self.assertItemsEqual(expected_keys, metadata.keys())
            self.assertNotEqual(1, metadata['data'])
            self.assertEqual(2, metadata['iterations'])
            self.assertEqual(128, len(metadata['salt']))
        finally:
            shutil.rmtree(tmp)
