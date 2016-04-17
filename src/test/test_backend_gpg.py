# -*- coding: utf-8 -*-
"""
test.test_backend_gpg
=====================

Tests the gpg backend.

:author: Joe Strickler <joe@decafjoe.com>
:copyright: Joe Strickler, 2016. All rights reserved.
:license: Proprietary
"""
import argparse
import os
import shutil
import tempfile
import unittest

import clik
import mock
import pexpect

from safe import GPGCryptographyError, GPGSafeBackend, GPG_DEFAULT_CIPHER


class GPGSafeBackendTest(unittest.TestCase):
    def context(self, ascii=False, cipher=GPG_DEFAULT_CIPHER):
        return clik.context(args=argparse.Namespace(
            gpg_ascii=ascii,
            gpg_cipher=cipher,
        ))

    @mock.patch('getpass.getpass', side_effect=['foo'])
    def test_read(self, _):
        safe = GPGSafeBackend()
        safe.password = 'bar'
        name = 'test_backend_gpg.gpg'
        path = os.path.join(os.path.dirname(__file__), name)
        with self.context():
            self.assertEqual(1, safe.read(path))

    @mock.patch('getpass.getpass', side_effect=('foo', 'foo'))
    def test_write(self, getpass):
        safe = GPGSafeBackend()
        tmp = tempfile.mkdtemp()
        try:
            path = os.path.join(tmp, 'test')
            with self.context():
                safe.write(path, 1)
            self.assertEqual(2, getpass.call_count)
            self.assertEqual('1', safe.decrypt(path, 'foo'))
            with self.context():
                safe.write(path, 1)
            self.assertEqual('1', safe.decrypt(path, 'foo'))
        finally:
            shutil.rmtree(tmp)

    def test_write_ascii(self):
        safe = GPGSafeBackend()
        safe.password = 'foo'
        tmp = tempfile.mkdtemp()
        try:
            path = os.path.join(tmp, 'test.gpg')
            with self.context(ascii=True):
                safe.write(path, 1)
            with open(path) as f:
                data = f.read()
            self.assertTrue(data.startswith('-----BEGIN PGP MESSAGE-----'))
        finally:
            shutil.rmtree(tmp)

    @mock.patch('pexpect.spawn')
    def test_write_error(self, process):
        safe = GPGSafeBackend()
        safe.password = 'foo'
        process.exitstatus = 1
        with self.context():
            self.assertRaises(GPGCryptographyError, safe.write, None, None)

    def test_write_specify_cipher(self):
        safe = GPGSafeBackend()
        safe.password = 'foo'
        tmp = tempfile.mkdtemp()
        try:
            path = os.path.join(tmp, 'test.gpg')
            with self.context(cipher='aes256'):
                safe.write(path, 1)
            command = ' '.join((
                GPGSafeBackend.gpg,
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
