# -*- coding: utf-8 -*-
"""
test.test_backend_bcrypt
========================

Tests the Bcrypt command-line tool backend.

:author: Joe Strickler <joe@decafjoe.com>
:copyright: Joe Strickler, 2016-2017. All rights reserved.
:license: Proprietary
"""
import argparse
import filecmp
import os
import platform
import shutil
import tempfile
import unittest

import clik
import mock

from safe import BcryptCryptographyError, BcryptFilenameError, \
    BcryptSafeBackend


class BcryptSafeBackendTestCase(unittest.TestCase):
    @property
    def bfe_path(self):
        fmt = 'test_backend_bcrypt.%s.bfe'
        name = fmt % ('mac' if platform.mac_ver()[0] else 'linux')
        return os.path.join(os.path.dirname(__file__), name)


class BcryptSafeBackendTest(BcryptSafeBackendTestCase):
    def context(self):
        return clik.context(args=argparse.Namespace(bcrypt_overwrites=1))

    def test_decrypt_non_bfe(self):
        safe = BcryptSafeBackend()
        self.assertRaises(BcryptFilenameError, safe.decrypt, 'foo', None)

    def test_encrypt_bfe(self):
        safe = BcryptSafeBackend()
        self.assertRaises(BcryptFilenameError, safe.encrypt, 'foo.bfe', None)

    @mock.patch('pexpect.spawn')
    def test_encrypt_error(self, process):
        safe = BcryptSafeBackend()
        process.exitstatus = 1
        with self.context():
            self.assertRaises(BcryptCryptographyError, safe.encrypt, '', None)

    @mock.patch('getpass.getpass', side_effect=['foofoofoo'])
    def test_read(self, _):
        safe = BcryptSafeBackend()
        safe.password = 'foo'
        with self.context():
            self.assertEqual([{u'foo': u'bar'}], safe.read(self.bfe_path))

    @mock.patch('sys.stderr')
    def test_write(self, stderr):
        safe = BcryptSafeBackend()
        answers = (
            'foo',
            'foo',
            'f' * 100,
            'f' * 100,
            'foofoofoo',
            'foofoofoo',
        )
        error_message = 'error: bcrypt passphrases must be 8 to 56 characters'
        tmp = tempfile.mkdtemp()
        try:
            path_actual = os.path.join(tmp, 'test')
            with mock.patch('getpass.getpass', side_effect=answers):
                with self.context():
                    safe.write(path_actual, [{u'foo': u'bar'}])
            self.assertEqual(4, stderr.write.call_count)
            first, second, third, fourth = stderr.write.call_args_list
            self.assertEqual(error_message, first[0][0])
            self.assertEqual('\n', second[0][0])
            self.assertEqual(error_message, third[0][0])
            self.assertEqual('\n', fourth[0][0])
            self.assertTrue(filecmp.cmp(self.bfe_path, path_actual))
            with self.context():
                safe.write(path_actual, [{u'foo': u'bar'}])
            self.assertTrue(filecmp.cmp(self.bfe_path, path_actual))
        finally:
            shutil.rmtree(tmp)

    def test_write_encrypt_error(self):
        def raise_exception(*args, **kwargs):
            raise TestException

        class TestException(Exception):
            pass

        safe = BcryptSafeBackend()
        safe.password = 'foofoofoo'
        safe.encrypt = mock.MagicMock(side_effect=raise_exception)
        fd, fp = tempfile.mkstemp()
        try:
            self.assertTrue(os.path.exists(fp))
            path = os.path.join(tempfile.gettempdir(), 'test')
            with mock.patch('tempfile.mkstemp') as mkstemp:
                mkstemp.return_value = fd, fp
                self.assertRaises(TestException, safe.write, path, 1)
            self.assertFalse(os.path.exists(fp))
        finally:
            if os.path.exists(fp):
                os.unlink(fp)

    def test_write_fdopen_error(self):
        safe = BcryptSafeBackend()
        safe.password = 'foofoofoo'
        fd, fp = tempfile.mkstemp()
        os.close(fd)
        try:
            self.assertTrue(os.path.exists(fp))
            path = os.path.join(tempfile.gettempdir(), 'test')
            with mock.patch('tempfile.mkstemp') as mkstemp:
                mkstemp.return_value = fd, fp
                self.assertRaises(OSError, safe.write, path, 1)
            self.assertFalse(os.path.exists(fp))
        finally:
            if os.path.exists(fp):
                os.unlink(fp)
