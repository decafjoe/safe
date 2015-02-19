"""
test.test_backend_gpg
=====================

Tests the gpg backend.

:copyright: (c) 2015 Joe Strickler
:license: BSD, see LICENSE for more details
"""
import filecmp
import os
import shutil
import tempfile
import unittest

import clik
import clik.util
import mock
import pexpect

from safe import GPGError, GPGSafeBackend, GPG, GPG_DEFAULT_CIPHER


class GPGSafeBackendTest(unittest.TestCase):
    def context(self, ascii=False, cipher=GPG_DEFAULT_CIPHER):
        return clik.context(args=clik.util.AttributeDict(
            gpg_ascii=ascii,
            gpg_cipher=cipher,
        ))

    def test_constructor(self):
        safe = GPGSafeBackend()
        self.assertIsNone(safe._password)

    @mock.patch('getpass.getpass', side_effect=['foo'])
    def test_read(self, _):
        safe = GPGSafeBackend()
        safe._password = 'bar'
        name = 'test_backend_gpg.gpg'
        path = os.path.join(os.path.dirname(__file__), name)
        with self.context():
            self.assertEqual(1, safe.read(path))

    def test_write(self):
        safe = GPGSafeBackend()
        safe._prompt_for_new_password = mock.MagicMock()
        safe._prompt_for_new_password.return_value = 'foo'
        tmp = tempfile.mkdtemp()
        try:
            path = os.path.join(tmp, 'test')
            with self.context():
                safe.write(path, 1)
            self.assertEqual('1', safe.decrypt(path, 'foo'))
            with self.context():
                safe.write(path, 1)
            self.assertEqual('1', safe.decrypt(path, 'foo'))
        finally:
            shutil.rmtree(tmp)

    def test_write_ascii(self):
        safe = GPGSafeBackend()
        safe._password = 'foo'
        tmp = tempfile.mkdtemp()
        try:
            path = os.path.join(tmp, 'test.gpg')
            with self.context(ascii=True):
                safe.write(path, 1)
            with open(path) as f:
                data = f.read()
            header = '-----BEGIN PGP MESSAGE-----'
            self.assertTrue(data.startswith(header))
        finally:
            shutil.rmtree(tmp)

    def test_write_error(self):
        safe = GPGSafeBackend()
        safe._password = 'foo'
        process = mock.MagicMock()
        process.exitstatus = 1
        safe._pexpect_spawn = mock.MagicMock(side_effect=[process])
        with self.context():
            self.assertRaises(GPGError, safe.write, None, None)

    def test_write_with_different_cipher(self):
        safe = GPGSafeBackend()
        safe._password = 'foo'
        tmp = tempfile.mkdtemp()
        try:
            path = os.path.join(tmp, 'test.gpg')
            with self.context(cipher='aes256'):
                safe.write(path, 1)
            command = ' '.join((
                GPG,
                '--batch',
                '--decrypt',
                '--passphrase',
                'foo',
                path,
            ))
            process = pexpect.spawn(command)
            out = process.read()
            process.close()
            self.assertEqual(0, process.exitstatus)
            lines = []
            saw_aes = False
            for line in out.splitlines():
                if line.startswith('gpg'):
                    if 'AES256 encrypted data' in line:
                        saw_aes = True
                else:
                    lines.append(line)
            self.assertEqual(1, len(lines))
            self.assertEqual('1', lines[0])
            self.assertTrue(saw_aes)
        finally:
            shutil.rmtree(tmp)
