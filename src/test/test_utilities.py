"""
test.test_utilities
===================

Tests the utility functions.

:copyright: (c) 2015 Joe Strickler
:license: BSD, see LICENSE for more details
"""
import unittest

import mock

from safe import prompt_for_new_password


class PromptForNewPasswordTest(unittest.TestCase):
    @mock.patch('getpass.getpass', side_effect=('foo', 'bar', 'foo', 'foo'))
    @mock.patch('sys.stderr')
    def test(self, stderr, _):
        self.assertEqual('foo', prompt_for_new_password())
        self.assertEqual(2, stderr.write.call_count)
        first, second = stderr.write.call_args_list
        self.assertEqual('error: passwords did not match', first[0][0])
        self.assertEqual('\n', second[0][0])
