# -*- coding: utf-8 -*-
"""
test.test_backend_fernet
========================

Tests the Fernet backend from the cryptography library.

:author: Joe Joyce <joe@decafjoe.com>
:copyright: Joe Joyce, 2016-2017. All rights reserved.
:license: Proprietary
"""
import argparse
import os
import shutil
import tempfile
import unittest

import clik
import mock

from safe import FernetSafeBackend, load_json


DATA = '{"salt": "ba583398762afa6ec570001a9115d6a2d0ab60df26480a57e3a3534825' \
       'ddb06f", "data": "gAAAAABU5PMizyV-SakJyAsXYNAoYVrMGUDZr02pYhvarO48j_' \
       'Qw6aovs3EuBGRJbgYdO1UTgSG7qIYaBhWOn0dXoXzLIF1TrQ==", "iterations": 1}'


class FernetSafeBackendTest(unittest.TestCase):
    def context(self, iterations=1, salt=32):
        return clik.context(args=argparse.Namespace(
            fernet_pbkdf2_iterations=iterations,
            fernet_pbkdf2_salt_length=salt,
        ))

    @mock.patch('getpass.getpass', side_effect=['foo'])
    def test_read(self, _):
        tmp = tempfile.mkdtemp()
        try:
            path = os.path.join(tmp, 'test')
            with open(path, 'w') as f:
                f.write(DATA)
            safe = FernetSafeBackend()
            safe.password = 'bar'
            with self.context():
                self.assertEqual(1, safe.read(path))
        finally:
            shutil.rmtree(tmp)

    @mock.patch('getpass.getpass', side_effect=('foo', 'foo'))
    def test_write(self, getpass):
        tmp = tempfile.mkdtemp()
        try:
            path = os.path.join(tmp, 'test')
            safe = FernetSafeBackend()
            expected_keys = ('data', 'iterations', 'salt')

            with self.context(1, 32):
                safe.write(path, 1)
            self.assertEqual(2, getpass.call_count)
            with open(path) as f:
                metadata = load_json(f)
            self.assertItemsEqual(expected_keys, metadata.keys())
            self.assertNotEqual(1, metadata['data'])
            self.assertEqual(1, metadata['iterations'])
            self.assertEqual(64, len(metadata['salt']))

            with self.context(2, 64):
                safe.write(path, 1)
            with open(path) as f:
                metadata = load_json(f)
            self.assertItemsEqual(expected_keys, metadata.keys())
            self.assertNotEqual(1, metadata['data'])
            self.assertEqual(2, metadata['iterations'])
            self.assertEqual(128, len(metadata['salt']))
        finally:
            shutil.rmtree(tmp)
