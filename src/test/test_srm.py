# -*- coding: utf-8 -*-
"""
Tests for :mod:`safe.srm`.

:author: Joe Joyce <joe@decafjoe.com>
:copyright: Copyright (c) Joe Joyce and contributors, 2016-2019.
:license: BSD
"""
import contextlib
import os
import stat

import mock
import pytest

from safe.srm import secure_delete, SecureDeleteError, SHRED_ITERATIONS
from safe.util import temporary_directory


@contextlib.contextmanager
def harness(filename=None, returncode=0, stdout='', stderr=''):
    """
    Set up test harness.

    This optionally creates a dummy executable named ``filename``, then
    "patches" that executable to return ``returncode`` as well as "output"
    ``stdout`` and ``stderr`` as specified.

    :param filename: Name of the fake executable to create, or ``None`` if
                     no fake executable should be created
    :type filename: :class:`str` or ``None``
    :param int returncode: Return code of the fake executable
    :param str stdout: Stdout for the fake executable
    :param str stderr: Stderr for the fake executable
    """
    with temporary_directory() as tmp:
        original_path = os.environ['PATH']
        os.environ['PATH'] = tmp
        try:
            path = None
            if filename:
                path = os.path.join(tmp, filename)
                with open(path, 'w') as f:
                    f.write('#!/bin/sh\n')
                os.chmod(path, stat.S_IRWXU)
            with mock.patch('safe.srm.Subprocess') as subprocess_constructor:
                process = mock.MagicMock()
                process.communicate.return_value = (stdout, stderr)
                process.returncode = returncode
                subprocess_constructor.return_value = process
                yield path, subprocess_constructor
        finally:
            os.environ['PATH'] = original_path


def test_srm():
    """Check successful srm call."""
    path = object()
    with harness('srm') as (executable, process):
        secure_delete(path)
    process.assert_called_once_with((executable, path))


def test_srm_fail():
    """Check failed srm call."""
    path = object()
    with harness('srm', 7, 'a', 'b'), pytest.raises(SecureDeleteError) as ei:
        secure_delete(path)
    e = ei.value
    assert '7' in e.message
    assert e.stdout == 'a'
    assert e.stderr == 'b'


def test_shred():
    """Check successful use of shred."""
    with temporary_directory() as tmp:
        path = os.path.join(tmp, 'test')
        with open(path, 'w') as f:
            f.write('\n')
        with harness('shred') as (executable, process):
            secure_delete(path)
        cmd = (executable, '--iterations', str(SHRED_ITERATIONS), path)
        process.assert_called_once_with(cmd)
        assert not os.path.exists(path)


def test_shred_fail():
    """Check ``shred`` executable failure."""
    path = object()
    with harness('shred', 7, 'a', 'b'), pytest.raises(SecureDeleteError) as ei:
        secure_delete(path)
    e = ei.value
    assert '7' in e.message
    assert e.stdout == 'a'
    assert e.stderr == 'b'


def test_missing():
    """Check exception is raised if no secure delete programs found."""
    with harness(), pytest.raises(SecureDeleteError) as ei:
        secure_delete(None)
    e = ei.value
    assert 'no secure delete' in e.message
    assert e.stdout is None
    assert e.stderr is None
