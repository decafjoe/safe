"""
test.test_backend_fernet
========================

Tests the Fernet backend from the cryptography library.

:copyright: (c) 2015 Joe Strickler
:license: BSD, see LICENSE for more details
"""
import base64
import os
import shutil
import tempfile
import unittest

import arrow
import clik
import clik.util
import mock

from safe import load_json, FernetSafeBackend


DATA = '{"salt": "ba583398762afa6ec570001a9115d6a2d0ab60df26480a57e3a3534825' \
       'ddb06f", "data": "gAAAAABU5PMizyV-SakJyAsXYNAoYVrMGUDZr02pYhvarO48j_' \
       'Qw6aovs3EuBGRJbgYdO1UTgSG7qIYaBhWOn0dXoXzLIF1TrQ==", "iterations": 1}'


class FernetSafeBackendTest(unittest.TestCase):
    def context(self, iterations=1, salt=32):
        return clik.context(args=clik.util.AttributeDict(
            fernet_pbkdf2_iterations=iterations,
            fernet_pbkdf2_salt_length=salt,
        ))

    def test_constructor(self):
        safe = FernetSafeBackend()
        self.assertEqual(None, safe._password)

    @mock.patch('getpass.getpass', side_effect=['foo'])
    def test_read(self, _):
        tmp = tempfile.mkdtemp()
        try:
            path = os.path.join(tmp, 'test')
            with open(path, 'w') as f:
                f.write(DATA)
            safe = FernetSafeBackend()
            safe._password = 'bar'
            with self.context():
                self.assertEqual(1, safe.read(path))
        finally:
            shutil.rmtree(tmp)

    def test_write(self):
        tmp = tempfile.mkdtemp()
        try:
            path = os.path.join(tmp, 'test')
            safe = FernetSafeBackend()
            safe._prompt_for_new_password = mock.MagicMock()
            safe._prompt_for_new_password.return_value = 'foo'
            expected_keys = ('data', 'iterations', 'salt')

            with self.context(1, 32):
                safe.write(path, 1)
            safe._prompt_for_new_password.assert_called_once_with()
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
