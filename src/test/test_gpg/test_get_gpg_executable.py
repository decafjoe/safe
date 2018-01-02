# -*- coding: utf-8 -*-
"""
Tests for :func:`safe.gpg.get_gpg_executable`.

:author: Joe Joyce <joe@decafjoe.com>
:copyright: Copyright (c) Joe Joyce and contributors, 2016-2018.
:license: BSD
"""
import contextlib
import os
import stat

import pytest

from safe.gpg import get_gpg_executable, GPGError
from safe.util import temporary_directory


@contextlib.contextmanager
def harness(filename=None, content=None):
    """
    Configure the harness for executable tests.

    This sets up the PATH and optionally populates a fake GPG executable
    named ``filename`` with the content ``content``.

    :param str filename: Name of the fake GPG executable
    :param str content: Content of the file (bash script)
    """
    if not content:
        content = ''
    with temporary_directory() as tmp:
        original_path = os.environ['PATH']
        os.environ['PATH'] = tmp
        try:
            path = None
            if filename:
                path = os.path.join(tmp, filename)
                with open(path, 'w') as f:
                    f.write('#!/bin/sh\n%s\n' % content)
                os.chmod(path, stat.S_IRWXU)
            yield path
        finally:
            os.environ['PATH'] = original_path


def test_gpg2():
    """Check gpg2."""
    with harness('gpg2') as path:
        assert path == get_gpg_executable()


def test_gpg():
    """Check gpg with a compatible version string."""
    version = 'gpg (GnuPG/SafeTest) 2.2.0'
    with harness('gpg', "echo '%s'" % version) as path:
        assert path == get_gpg_executable()


def test_missing():
    """Check error is raised when no gpg executables exist."""
    with harness(), pytest.raises(GPGError) as ei:
        get_gpg_executable()
    e = ei.value
    assert 'gpg2' in e.message
    assert e.stdout is None
    assert e.stderr is None


def test_gpg_version_fail():
    """Check error is raised when ``gpg --version`` fails."""
    with harness('gpg', 'exit 1'), pytest.raises(GPGError) as ei:
        get_gpg_executable()
    e = ei.value
    assert 'non-zero' in e.message
    assert '' == e.stdout
    assert e.stderr is None


def test_gpg_version_regex():
    """Check error is raised when ``gpg --version`` cannot be interpreted."""
    with harness('gpg', 'echo whoops'), pytest.raises(GPGError) as ei:
        get_gpg_executable()
    e = ei.value
    assert 'could not extract' in e.message
    assert 'whoops' == e.stdout.strip()
    assert e.stderr is None


def test_gpg_major_version_mismatch():
    """Check error is raised when ``gpg --version`` returns version 1."""
    version = 'gpg (GnuPG/SafeTest) 1.14.12'
    with harness('gpg', "echo '%s'" % version), pytest.raises(GPGError) as ei:
        get_gpg_executable()
    e = ei.value
    assert 'requires gpg version 2' in e.message
    assert 'found version: 1' in e.message
    assert version == e.stdout.strip()
    assert e.stderr is None
