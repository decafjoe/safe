"""
test.test_copy
==============

Tests copy command.

:copyright: (c) 2015 Joe Strickler
:license: BSD, see LICENSE for more details
"""
import filecmp
import os
import shutil
import tempfile

import mock

from test import safe, TemporaryFileTestCase


class CopyTest(TemporaryFileTestCase):
    def setUp(self):  # noqa
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):  # noqa
        shutil.rmtree(self.tmp)

    def test_copy(self):
        answers = (
            'foofoofoo',  # new password (plaintext -> bcrypt)
            'foofoofoo',  # confirm (plaintext -> bcrypt)
            'foofoofoo',  # decrypt safe (bcrypt -> bcrypt, password change)
            'foofoofoo',  # new password (bcrypt -> bcrypt, password change)
            'foofoofoo',  # confirm (bcrypt -> bcrypt, password change)
            'foofoofoo',  # decrypt safe (bcrypt -> bcrypt)
        )
        path1 = os.path.join(self.tmp, 'test1')
        path2 = os.path.join(self.tmp, 'test2')
        name = 'test_backend_bcrypt.bfe'
        path_expected = os.path.join(os.path.dirname(__file__), name)
        with mock.patch('getpass.getpass', side_effect=answers) as getpass:
            # plaintext -> bcrypt
            with self.temporary_file('[{"foo": "bar"}]') as fp:
                args = (
                    '-bplaintext',
                    '--bcrypt-overwrites',
                    '1',
                    '-f',
                    fp,
                    'cp',
                    '-bbcrypt',
                    path1,
                )
                rv, stdout, stderr = safe(*args)
            self.assertEqual(0, rv)
            self.assertEqual('', stdout)
            self.assertEqual('', stderr)
            self.assertEqual(2, getpass.call_count)
            self.assertTrue(filecmp.cmp(path_expected, path1))

            # bcrypt -> bcrypt, password change
            shutil.copy(path_expected, path1)
            args = (
                '-bbcrypt',
                '--bcrypt-overwrites',
                '1',
                '-f',
                path1,
                'cp',
                '-c',
                path2,
            )
            rv, stdout, stderr = safe(*args)
            self.assertEqual(0, rv)
            self.assertEqual('', stdout)
            self.assertEqual('', stderr)
            self.assertEqual(5, getpass.call_count)
            self.assertTrue(filecmp.cmp(path_expected, path2))

            # bcrypt -> bcrypt
            os.unlink(path2)
            args = (
                '-bbcrypt',
                '--bcrypt-overwrites',
                '1',
                '-f',
                path1,
                'cp',
                path2,
            )
            rv, stdout, stderr = safe(*args)
            self.assertEqual(0, rv)
            self.assertEqual('', stdout)
            self.assertEqual('', stderr)
            self.assertEqual(6, getpass.call_count)
            self.assertTrue(filecmp.cmp(path_expected, path2))

    def test_noop(self):
        path = os.path.join(self.tmp, 'test')
        other_path = os.path.join(self.tmp, 'another_test')
        for path_arguments in ((), (path,), (other_path,)):
            test_path = path
            if len(path_arguments) > 0:
                test_path = path_arguments[0]
                self.assertFalse(os.path.exists(test_path))
            rv, stdout, stderr = safe('-f', path, 'cp', *path_arguments)
            self.assertEqual(0, rv)
            self.assertEqual('', stdout)
            self.assertEqual('', stderr)
            self.assertFalse(os.path.exists(test_path))

    def test_overwrite(self):
        answers = ['', 'maybe', 'N', 'Y']

        def raw_input_mock(prompt):
            return answers.pop(0)

        path = os.path.join(self.tmp, 'test')
        prompt = mock.call('Overwrite %s? [y/N] ' % path)
        with open(path, 'w') as f:
            f.write('2')
        with self.temporary_file('[{"foo": "bar"}]') as fp:
            name = '__builtin__.raw_input'
            with mock.patch(name, side_effect=raw_input_mock) as raw_input:
                args = ('-bplaintext', '-f', fp, 'cp', path)
                rv, stdout, stderr = safe(*args)
                self.assertEqual(100, rv)
                self.assertEqual('', stdout)
                self.assertEqual('', stderr)
                self.assertEqual([prompt], raw_input.call_args_list)
                with open(path) as f:
                    self.assertEqual('2', f.read())

                rv, stdout, stderr = safe(*args)
                self.assertEqual(100, rv)
                self.assertEqual('', stdout)
                self.assertEqual('', stderr)
                self.assertEqual([prompt] * 3, raw_input.call_args_list)
                with open(path) as f:
                    self.assertEqual('2', f.read())

                rv, stdout, stderr = safe(*args)
                self.assertEqual(0, rv)
                self.assertEqual('', stdout)
                self.assertEqual('', stderr)
                self.assertEqual([prompt] * 4, raw_input.call_args_list)
                with open(path) as f:
                    self.assertEqual('[{"foo": "bar"}]', f.read())
