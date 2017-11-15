# -*- coding: utf-8 -*-
"""
Tests for :func:`safe.util.expand_path`.

:author: Joe Joyce <joe@decafjoe.com>
:copyright: Copyright (c) Joe Joyce and contributors, 2016-2017.
:license: BSD
"""
import os
import pwd

from safe.util import expand_path


HOME = pwd.getpwuid(os.getuid()).pw_dir


def test_absolute():
    """Check that absolute paths are returned unchanged."""
    assert '/tmp/foo' == expand_path('/tmp/foo')


def test_relative():
    """Check that relative paths are resolved to absolute paths."""
    cwd = os.getcwd()
    directory = os.path.dirname(__file__)
    os.chdir(directory)
    try:
        filename = os.path.split(__file__)[1]
        assert __file__ == expand_path(filename)
    finally:
        os.chdir(cwd)


def test_user():
    """Check that tilde is resolved to the home directory."""
    assert HOME == expand_path('~')


def test_envvar():
    """Check that environment variables are properly substituted."""
    envvar = 'SAFE_TEST_EXPAND_PATH_VAR'
    os.environ[envvar] = '/foo'
    try:
        assert '/foo' == expand_path('$%s' % envvar)
    finally:
        del os.environ[envvar]


def test_nested():
    """Check that an envvar referencing ``~`` resolves correctly."""
    envvar = 'SAFE_TEST_EXPAND_PATH_VAR'
    os.environ[envvar] = '~'
    try:
        assert HOME == expand_path('$%s' % envvar)
    finally:
        del os.environ[envvar]
