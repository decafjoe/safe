"""
test.test_backend_bcrypt
========================

Tests the Bcrypt command-line tool backend.

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

from safe import BcryptError, BcryptSafeBackend


class BcryptSafeBackendTest(unittest.TestCase):
    def context(self):
        return clik.context(args=clik.util.AttributeDict(
            bcrypt_overwrites=1,
        ))

    def test_constructor(self):
        safe = BcryptSafeBackend()
        self.assertIsNone(safe._password)

    def test_encrypt_error(self):
        safe = BcryptSafeBackend()
        process = mock.MagicMock()
        process.exitstatus = 1
        safe._pexpect_spawn = mock.MagicMock(side_effect=[process])
        with self.context():
            self.assertRaises(BcryptError, safe.encrypt, None, None)

    @mock.patch('getpass.getpass', side_effect=['foofoofoo'])
    def test_read(self, _):
        safe = BcryptSafeBackend()
        safe._password = 'foo'
        name = 'test_backend_bcrypt.bfe'
        path = os.path.join(os.path.dirname(__file__), name)
        with self.context():
            self.assertEqual(1, safe.read(path))

    @mock.patch('sys.stderr')
    def test_write(self, stderr):
        safe = BcryptSafeBackend()
        passwords = ('foo', 'f' * 100, 'foofoofoo')
        safe._prompt_for_new_password = mock.MagicMock(side_effect=passwords)
        name = 'test_backend_bcrypt.bfe'
        path_expected = os.path.join(os.path.dirname(__file__), name)
        error_message = 'error: bcrypt passphrases must be 8 to 56 characters'
        tmp = tempfile.mkdtemp()
        try:
            path_actual = os.path.join(tmp, 'test')
            with self.context():
                safe.write(path_actual, 1)
            self.assertEqual(4, stderr.write.call_count)
            first, second, third, fourth = stderr.write.call_args_list
            self.assertEqual(error_message, first[0][0])
            self.assertEqual('\n', second[0][0])
            self.assertEqual(error_message, third[0][0])
            self.assertEqual('\n', fourth[0][0])
            self.assertTrue(filecmp.cmp(path_expected, path_actual))
            with self.context():
                safe.write(path_actual, 1)
            self.assertTrue(filecmp.cmp(path_expected, path_actual))
        finally:
            shutil.rmtree(tmp)

    def test_write_encrypt_error(self):
        def raise_exception(*args, **kwargs):
            raise TestException

        class TestException(Exception):
            pass

        safe = BcryptSafeBackend()
        safe._password = 'foofoofoo'
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
        safe._password = 'foofoofoo'
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
