# -*- coding: utf-8 -*-
"""
test.test_utilities
===================

Tests the utility functions.

:author: Joe Strickler <joe@decafjoe.com>
:copyright: Joe Strickler, 2016. All rights reserved.
:license: Proprietary
"""
import argparse
import os
import unittest

import clik
import mock

from safe import expand_path, generate_key, get_executable, \
    prompt_boolean, prompt_for_new_password, prompt_until_decrypted, \
    prompt_until_decrypted_pbkdf2, SafeCryptographyError, \
    PBKDF2_DEFAULT_ITERATIONS, PBKDF2_DEFAULT_SALT_LENGTH


class ExpandPathTest(unittest.TestCase):
    def test_absolute_path(self):
        self.assertEqual('/tmp/foo', expand_path('/tmp/foo'))

    def test_nested(self):
        os.environ['SAFE_TEST_EXPAND_PATH_VAR'] = '~'
        try:
            path = expand_path('$SAFE_TEST_EXPAND_PATH_VAR')
            self.assertEqual(os.environ['HOME'], path)
        finally:
            del os.environ['SAFE_TEST_EXPAND_PATH_VAR']

    def test_relative(self):
        cwd = os.getcwd()
        directory = os.path.dirname(__file__)
        os.chdir(directory)
        try:
            filename = os.path.split(__file__)[1]
            self.assertEqual(__file__, expand_path(filename))
        finally:
            os.chdir(cwd)

    def test_user(self):
        self.assertEqual(os.environ['HOME'], expand_path('~'))

    def test_var(self):
        os.environ['SAFE_TEST_EXPAND_PATH_VAR'] = '/foo'
        try:
            self.assertEqual('/foo', expand_path('$SAFE_TEST_EXPAND_PATH_VAR'))
        finally:
            del os.environ['SAFE_TEST_EXPAND_PATH_VAR']


class GenerateKeyTest(unittest.TestCase):
    def context(self, **kwargs):
        return clik.context(args=argparse.Namespace(**kwargs))

    def test_nacl_backend(self):
        with self.context(nacl_pbkdf2_iterations=1, nacl_pbkdf2_salt_length=8):
            _, iterations, salt = generate_key('foo', 32, 'nacl')
        self.assertEqual(1, iterations)
        self.assertEqual(16, len(salt))

    def test_no_backend(self):
        with self.context():
            _, iterations, salt = generate_key('foo', 32)
        self.assertEqual(PBKDF2_DEFAULT_ITERATIONS, iterations)
        self.assertEqual(PBKDF2_DEFAULT_SALT_LENGTH * 2, len(salt))


class GetExecutableTest(unittest.TestCase):
    def test(self):
        self.assertEqual('/bin/ls', get_executable('ls'))
        self.assertIsNone(get_executable('this_should_not_exist'))


class PromptBooleanTest(unittest.TestCase):
    def assert_value(self, default, postfix):
        answers = ['', 'maybe', 'Y', 'N']

        def raw_input_mock(_):
            return answers.pop(0)

        prompt = 'Foo?'
        prompt_call = mock.call('Foo? %s ' % postfix)
        name = '__builtin__.raw_input'
        with mock.patch(name, side_effect=raw_input_mock) as raw_input:
            self.assertIs(default, prompt_boolean(prompt, default))
            self.assertEqual([prompt_call], raw_input.call_args_list)
            self.assertTrue(prompt_boolean(prompt, default))
            self.assertEqual([prompt_call] * 3, raw_input.call_args_list)
            self.assertFalse(prompt_boolean(prompt, default))
            self.assertEqual([prompt_call] * 4, raw_input.call_args_list)

    def test_false(self):
        self.assert_value(False, '[y/N]')

    def test_true(self):
        self.assert_value(True, '[Y/n]')


class PromptForNewPasswordTest(unittest.TestCase):
    @mock.patch('getpass.getpass', side_effect=('foo', 'bar', 'foo', 'foo'))
    @mock.patch('sys.stderr')
    def test(self, stderr, _):
        self.assertEqual('foo', prompt_for_new_password())
        self.assertEqual(2, stderr.write.call_count)
        first, second = stderr.write.call_args_list
        self.assertEqual('error: passwords did not match', first[0][0])
        self.assertEqual('\n', second[0][0])


class PromptUntilDecryptedTest(unittest.TestCase):
    @mock.patch('getpass.getpass', side_effect=('bar', 'foo'))
    @mock.patch('sys.stderr')
    def test(self, stderr, _):
        def decrypt(password):
            if password == 'foo':
                return '1'
            raise TestError

        class TestError(SafeCryptographyError):
            pass

        password, data = prompt_until_decrypted(decrypt, 'baz')
        self.assertEqual('foo', password)
        self.assertEqual(1, data)
        self.assertEqual(2, stderr.write.call_count)
        first, second = stderr.write.call_args_list
        self.assertEqual('error: failed to decrypt safe', first[0][0])
        self.assertEqual('\n', second[0][0])


class PromptUntilDecryptedPBKDF2Test(unittest.TestCase):
    @mock.patch('getpass.getpass', side_effect=('bar', 'foo'))
    @mock.patch('sys.stderr')
    def test(self, _1, _2):
        def decrypt(data, key):
            if key == 'Gn3O7sOd3f84uVvOOTUpJAvfATIxvV0Xs4m2PrakxVg=':
                return '1'
            raise TestError

        class TestError(SafeCryptographyError):
            pass

        password, data = prompt_until_decrypted_pbkdf2(
            decrypt,
            dict(data=None, iterations=1, salt='x'),
            32,
            'baz',
        )
        self.assertEqual(password, 'foo')
        self.assertEqual(1, data)
