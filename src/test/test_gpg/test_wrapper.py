# -*- coding: utf-8 -*-
"""
Tests for :class:`safe.gpg.GPGFile`.

:author: Joe Joyce <joe@decafjoe.com>
:copyright: Copyright (c) Joe Joyce and contributors, 2016-2017.
:license: BSD
"""
import os

import pytest

from safe.gpg import GPGError, GPGFile, GPGSubprocess
from safe.util import temporary_directory


CONTENT = 'hello'
ASYMMETRIC_KEYID = '81A375A2DC9B70881F65402F5DF95704FE4FD2BC'
SYMMETRIC_PASSWORD = 'password'


files_path = os.path.join(os.path.dirname(__file__), 'files')
asymmetric_path = os.path.join(files_path, 'asymmetric.asc')
public_path = os.path.join(files_path, 'public.asc')
secret_path = os.path.join(files_path, 'secret.asc')
symmetric_path = os.path.join(files_path, 'symmetric.asc')
trustdb_path = os.path.join(files_path, 'trustdb.txt')


def assert_crypto(gpg_file, tmp, password=None):
    ciphertext = os.path.join(tmp, 'ciphertext')
    plaintext_1 = os.path.join(tmp, 'plaintext-1')
    plaintext_2 = os.path.join(tmp, 'plaintext-2')
    gpg_file.decrypt_to(plaintext_1, password)
    with open(plaintext_1) as f:
        assert CONTENT == f.read().strip()
    gpg_file._path = ciphertext
    gpg_file.save(plaintext_1)
    gpg_file.decrypt_to(plaintext_2, password)
    with open(plaintext_2) as f:
        assert CONTENT == f.read().strip()


def setup_asymmetric(tmp, secret=True):
    def run(*command):
        process = GPGSubprocess(('--homedir', tmp) + command)
        process.wait()
        assert not process.returncode

    run('--import', public_path)
    run('--import-ownertrust', trustdb_path)
    if secret:
        run('--import', secret_path)


def test_symmetric_attribute():
    assert GPGFile(symmetric_path).symmetric is True
    assert GPGFile(asymmetric_path).symmetric is False


def test_asymmetric_happy_path():
    gpg_file = GPGFile(asymmetric_path)
    with temporary_directory() as tmp:
        setup_asymmetric(tmp)
        gpg_file._homedir = tmp
        assert_crypto(gpg_file, tmp)


def test_symmetric_happy_path():
    gpg_file = GPGFile(symmetric_path)
    with temporary_directory() as tmp:
        assert_crypto(gpg_file, tmp, SYMMETRIC_PASSWORD)


def test_invalid_file():
    with temporary_directory() as tmp, pytest.raises(GPGError) as ei:
        tmp_path = os.path.join(tmp, 'f')
        with open(tmp_path, 'w') as f:
            f.write('not a gpg file')
        GPGFile(tmp_path)
    e = ei.value
    assert 'encryption type packet' in e.message


def test_symmetric_no_password():
    with temporary_directory() as tmp, pytest.raises(Exception) as ei:
        GPGFile(symmetric_path).decrypt_to(os.path.join(tmp, 'f'))
    e = ei.value
    assert 'password required' in str(e)


def test_symmetric_invalid_password():
    with temporary_directory() as tmp, pytest.raises(GPGError) as ei:
        GPGFile(symmetric_path).decrypt_to(os.path.join(tmp, 'f'), 'wrong')
    e = ei.value
    assert 'failed to decrypt' in e.message
    assert 'bad session key' in e.stderr.lower()


def test_asymmetric_missing_key():
    with temporary_directory() as tmp, pytest.raises(GPGError) as ei:
        setup_asymmetric(tmp, secret=False)
        GPGFile(asymmetric_path).decrypt_to(os.path.join(tmp, 'f'))
    e = ei.value
    assert 'failed to decrypt' in e.message
    assert 'no secret key' in e.stderr.lower()


def test_asymmetric_reencryption_fails():
    gpg_file = GPGFile(asymmetric_path)
    with temporary_directory() as tmp, pytest.raises(GPGError) as ei:
        setup_asymmetric(tmp)
        gpg_file._homedir = tmp
        ciphertext = os.path.join(tmp, 'ciphertext')
        plaintext = os.path.join(tmp, 'plaintext-1')
        gpg_file.decrypt_to(plaintext)
        process = GPGSubprocess((
            '--batch',
            '--homedir', tmp,
            '--quiet',
            '--yes',
            '--delete-secret-and-public-key', ASYMMETRIC_KEYID,
        ))
        process.wait()
        assert not process.returncode
        gpg_file._path = ciphertext
        gpg_file.save(plaintext)
    e = ei.value
    assert 'failed to re-encrypt' in e.message
    assert 'no public key' in e.stderr.lower()
