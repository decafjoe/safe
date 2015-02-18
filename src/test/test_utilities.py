"""
test.test_utilities
===================

Tests the utility functions.

:copyright: (c) 2015 Joe Strickler
:license: BSD, see LICENSE for more details
"""
import unittest

import clik
import clik.util
import mock

from safe import generate_key, prompt_for_new_password, \
    PBKDF2_DEFAULT_ITERATIONS, PBKDF2_DEFAULT_SALT_LENGTH


class GenerateKeyTest(unittest.TestCase):
    def context(self, **kwargs):
        return clik.context(args=clik.util.AttributeDict(kwargs))

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


class PromptForNewPasswordTest(unittest.TestCase):
    @mock.patch('getpass.getpass', side_effect=('foo', 'bar', 'foo', 'foo'))
    @mock.patch('sys.stderr')
    def test(self, stderr, _):
        self.assertEqual('foo', prompt_for_new_password())
        self.assertEqual(2, stderr.write.call_count)
        first, second = stderr.write.call_args_list
        self.assertEqual('error: passwords did not match', first[0][0])
        self.assertEqual('\n', second[0][0])
