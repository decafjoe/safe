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

from clik import g

import safe as safe_mod
from safe import safe as safe_app, PBKDF2_DEFAULT_ITERATIONS, \
    PBKDF2_DEFAULT_SALT_LENGTH

from test import backend, safe, TemporaryFileTestCase


class ApplicationTest(TemporaryFileTestCase):
    @contextlib.contextmanager
    def envvar(self, **kwargs):
        original = dict()
        for key, value in kwargs.iteritems():
            if key in os.environ:
                original[key] = os.environ[key]
            os.environ[key] = value
        yield
        for key, value in kwargs.iteritems():
            if key in original:
                os.environ[key] = original[key]
            else:
                del os.environ[key]

    def test_arguments(self):
        rv, stdout, stderr = safe('--help')
        self.assertEqual(0, rv)
        expected_strings = (
            '--backend',
            '(default: gpg)',
            '--file',
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
            with self.temporary_file('[{"foo": "bar"}]') as fp:
                with backend('plaintext'):
                    rv, stdout, stderr = safe('-f', fp, 'test')
                self.assertEqual(42, rv)
                self.assertEqual('', stdout)
                self.assertEqual('', stderr)
                with open(fp) as f:
                    self.assertEqual('[{"foo": "bar"}]', f.read())
        finally:
            del safe_app.children[-1]

    def test_envvar_backend(self):
        @safe_app
        def test():
            yield
            print g.data

        try:
            with self.temporary_file('[{"foo": "bar"}]') as fp:
                with self.envvar(SAFE_BACKEND='plaintext'):
                    rv, stdout, stderr = safe('-f', fp, 'test')
        finally:
            del safe_app.children[-1]

        self.assertEqual(0, rv)
        self.assertEqual("[{u'foo': u'bar'}]\n", stdout)
        self.assertEqual('', stderr)

    def test_envvar_invalid_backend(self):
        @safe_app
        def test():
            yield
            print g.safe.__class__.__name__

        try:
            with backend('plaintext'), self.envvar(SAFE_BACKEND='foo'):
                rv, stdout, stderr = safe('-fx', 'test')
        finally:
            del safe_app.children[-1]

        self.assertEqual(0, rv)
        self.assertEqual('PlaintextSafeBackend\n', stdout)
        msg = 'warning: SAFE_BACKEND specifies an unknown backend: foo\n'
        self.assertEqual(msg, stderr)

    def test_envvar_path(self):
        @safe_app
        def test():
            yield
            print g.path

        try:
            with self.envvar(SAFE_PATH='/foo/bar/baz'):
                rv, stdout, stderr = safe('test')
        finally:
            del safe_app.children[-1]

        self.assertEqual(0, rv)
        self.assertEqual('/foo/bar/baz\n', stdout)
        self.assertEqual('', stderr)

    def test_keyboard_interrupt(self):
        @safe_app
        def test():
            yield
            raise KeyboardInterrupt

        try:
            rv, stdout, stderr = safe('-fx', 'test')
        finally:
            del safe_app.children[-1]

        self.assertEqual(10, rv)
        self.assertEqual('\n', stdout)
        self.assertEqual('', stderr)

    def test_kill_data(self):
        @safe_app
        def test():
            yield
            g.data = None

        try:
            with self.temporary_file('[{"foo": "bar"}]') as fp:
                with backend('plaintext'):
                    rv, stdout, stderr = safe('-f', fp, 'test')
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
                with backend('plaintext'):
                    rv, stdout, stderr = safe('-f', path, 'test')
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
                rv, stdout, stderr = safe('-f', path, 'test')
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
            with self.temporary_file('[{"foo": "bar"}]') as fp:
                with backend('plaintext'):
                    rv, stdout, stderr = safe('-f', fp, 'test')
                self.assertEqual(0, rv)
                self.assertEqual("[{u'foo': u'bar'}]\n", stdout)
                self.assertEqual('', stderr)
        finally:
            del safe_app.children[-1]

    def test_update(self):
        @safe_app
        def test():
            yield
            g.data[0]['foo'] = 'baz'

        try:
            with self.temporary_file('[{"foo": "bar"}]') as fp:
                with backend('plaintext'):
                    rv, stdout, stderr = safe('-f', fp, 'test')
                self.assertEqual(0, rv)
                self.assertEqual('', stdout)
                self.assertEqual('', stderr)
                with open(fp) as f:
                    self.assertEqual('[{"foo": "baz"}]', f.read())
        finally:
            del safe_app.children[-1]

    def test_unavailable_backend(self):
        safe_mod.PREFERRED_BACKENDS = ('foo',) + safe_mod.PREFERRED_BACKENDS
        rv, stdout, stderr = safe('--help')
        self.assertEqual(0, rv)
        self.assertFalse('foo' in stdout)
