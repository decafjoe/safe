"""
test.test_backend_nacl
======================

Test the PyNaCl backend.

:copyright: (c) 2015 Joe Strickler
:license: BSD, see LICENSE for more details
"""
import base64
import os
import shutil
import tempfile
import unittest

import clik
import clik.util
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
        return clik.context(args=clik.util.AttributeDict(
            nacl_pbkdf2_iterations=iterations,
            nacl_pbkdf2_salt_length=salt,
        ))

    def test_constructor(self):
        safe = NaClSafeBackend()
        self.assertEqual(-1, safe._nonce)
        self.assertEqual(None, safe._password)

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

    @mock.patch('getpass.getpass', side_effect=['bar', 'foo'])
    @mock.patch('sys.stderr')
    def test_read(self, stderr, _):
        tmp = tempfile.mkdtemp()
        try:
            path = os.path.join(tmp, 'test')
            with open(path, 'w') as f:
                f.write(DATA)
            safe = NaClSafeBackend()
            safe._password = 'bar'
            with self.context(1, 32):
                self.assertEqual(1, safe.read(path))
            self.assertEqual(2, stderr.write.call_count)
            first, second = stderr.write.call_args_list
            self.assertEqual('error: failed to decrypt safe', first[0][0])
            self.assertEqual('\n', second[0][0])
        finally:
            shutil.rmtree(tmp)

    def test_write(self):
        tmp = tempfile.mkdtemp()
        try:
            path = os.path.join(tmp, 'test')
            safe = NaClSafeBackend()
            safe._prompt_for_new_password = mock.MagicMock()
            safe._prompt_for_new_password.return_value = 'foo'
            expected_keys = ('data', 'iterations', 'nonce', 'salt')

            with self.context(1, 32):
                safe.write(path, 1)
            self.assertEqual(0, safe._nonce)
            safe._prompt_for_new_password.assert_called_once_with()
            with open(path) as f:
                metadata = load_json(f)
            self.assertItemsEqual(expected_keys, metadata.keys())
            self.assertNotEqual(1, metadata['data'])
            self.assertEqual(1, metadata['iterations'])
            self.assertEqual('000000000000000000000000', metadata['nonce'])
            self.assertEqual(64, len(metadata['salt']))

            with self.context(2, 64):
                safe.write(path, 1)
            self.assertEqual(1, safe._nonce)
            with open(path) as f:
                metadata = load_json(f)
            self.assertItemsEqual(expected_keys, metadata.keys())
            self.assertNotEqual(1, metadata['data'])
            self.assertEqual(2, metadata['iterations'])
            self.assertEqual('000000000000000000000001', metadata['nonce'])
            self.assertEqual(128, len(metadata['salt']))
        finally:
            shutil.rmtree(tmp)
