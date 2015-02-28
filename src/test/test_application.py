"""
test.test_application
=====================

Tests :func:`safe.safe`.

:copyright: (c) 2015 Joe Strickler
:license: BSD, see LICENSE for more details
"""
import contextlib
import os
import shutil
import tempfile
import unittest

from clik import g

import safe as safe_mod
from safe import safe as safe_app, PBKDF2_DEFAULT_ITERATIONS, \
    PBKDF2_DEFAULT_SALT_LENGTH

from test import safe


class ApplicationTest(unittest.TestCase):
    @contextlib.contextmanager
    def temporary_file(self, content):
        fd, fp = tempfile.mkstemp()
        try:
            f = os.fdopen(fd, 'w')
        except:
            os.close(fd)
            os.unlink(fp)
            raise
        try:
            f.write(content)
        except:
            f.close()
            os.unlink(fp)
            raise
        f.close()
        try:
            yield fp
        finally:
            os.unlink(fp)

    def test_arguments(self):
        rv, stdout, stderr = safe('--help')
        self.assertEqual(0, rv)
        expected_strings = (
            '--backend',
            '(default: gpg)',
            '--bcrypt-overwrites',
            '--fernet-pbkdf2-iterations',
            '(default: %i)' % PBKDF2_DEFAULT_ITERATIONS,
            '--fernet-pbkdf2-salt-length',
            '(default: %i)' % PBKDF2_DEFAULT_SALT_LENGTH,
            '--gpg-ascii',
            '--gpg-cipher',
            '3des',
            'aes256',
            'blowfish',
            'idea',
            '--nacl-pbkdf2-iterations',
            '(default: %i)' % PBKDF2_DEFAULT_ITERATIONS,
            '--nacl-pbkdf2-salt-length',
            '(default: %i)' % PBKDF2_DEFAULT_SALT_LENGTH,
            'required arguments',
            '--file',
        )
        index = 0
        for string in expected_strings:
            msg = 'failed to find "%s" after index %i' % (string, index)
            index = stdout.find(string, index)
            self.assertNotEqual(-1, index, msg)

    def test_command_failure(self):
        @safe_app
        def test():
            yield
            g.data = 2
            yield 42

        try:
            with self.temporary_file('1') as fp:
                rv, stdout, stderr = safe('-bplaintext', '-f%s' % fp, 'test')
                self.assertEqual(42, rv)
                self.assertEqual('', stdout)
                self.assertEqual('', stderr)
                with open(fp) as f:
                    self.assertEqual('1', f.read())
        finally:
            del safe_app.children[-1]

    def test_keyboard_interrupt(self):
        @safe_app
        def test():
            yield
            raise KeyboardInterrupt

        try:
            rv, stdout, stderr = safe('-fdoes_not_exist', 'test')
            self.assertEqual(10, rv)
            self.assertEqual('\n', stdout)
            self.assertEqual('', stderr)
        finally:
            del safe_app.children[-1]

    def test_kill_data(self):
        @safe_app
        def test():
            yield
            g.data = None

        try:
            with self.temporary_file('1') as fp:
                rv, stdout, stderr = safe('-bplaintext', '-f%s' % fp, 'test')
                self.assertEqual(0, rv)
                self.assertEqual('', stdout)
                self.assertEqual('', stderr)
                self.assertTrue(os.path.exists(fp))
                with open(fp) as f:
                    self.assertEqual('null', f.read())
        finally:
            del safe_app.children[-1]

    def test_new(self):
        @safe_app
        def test():
            yield
            g.data = 1

        try:
            tmp = tempfile.mkdtemp()
            try:
                path = os.path.join(tmp, 'test')
                self.assertFalse(os.path.exists(path))
                args = ('-bplaintext', '-f%s' % path, 'test')
                rv, stdout, stderr = safe(*args)
                self.assertEqual(0, rv)
                self.assertEqual('', stdout)
                self.assertEqual('', stderr)
                self.assertTrue(os.path.exists(path))
                with open(path) as f:
                    self.assertEqual('1', f.read())
            finally:
                shutil.rmtree(tmp)
        finally:
            del safe_app.children[-1]

    def test_noop(self):
        @safe_app
        def test():
            yield

        try:
            tmp = tempfile.mkdtemp()
            try:
                path = os.path.join(tmp, 'test')
                rv, stdout, stderr = safe('-f%s' % path, 'test')
                self.assertEqual(0, rv)
                self.assertEqual('', stdout)
                self.assertEqual('', stderr)
                self.assertFalse(os.path.exists(path))
            finally:
                shutil.rmtree(tmp)
        finally:
            del safe_app.children[-1]

    def test_read(self):
        @safe_app
        def test():
            yield
            print g.data

        try:
            with self.temporary_file('1') as fp:
                rv, stdout, stderr = safe('-bplaintext', '-f%s' % fp, 'test')
                self.assertEqual(0, rv)
                self.assertEqual('1\n', stdout)
                self.assertEqual('', stderr)
        finally:
            del safe_app.children[-1]

    def test_update(self):
        @safe_app
        def test():
            yield
            g.data = 2

        try:
            with self.temporary_file('1') as fp:
                args = ('-bplaintext', '-f%s' % fp, 'test')
                rv, stdout, stderr = safe(*args)
                self.assertEqual(0, rv)
                self.assertEqual('', stdout)
                self.assertEqual('', stderr)
                with open(fp) as f:
                    self.assertEqual('2', f.read())
        finally:
            del safe_app.children[-1]

    def test_unavailable_backend(self):
        safe_mod.PREFERRED_BACKENDS = ('foo',) + safe_mod.PREFERRED_BACKENDS
        rv, stdout, stderr = safe('--help')
        self.assertEqual(0, rv)
        self.assertFalse('foo' in stdout)
