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
    assert '/tmp/foo' == expand_path('/tmp/foo')


def test_relative():
    cwd = os.getcwd()
    directory = os.path.dirname(__file__)
    os.chdir(directory)
    try:
        filename = os.path.split(__file__)[1]
        assert __file__ == expand_path(filename)
    finally:
        os.chdir(cwd)


def test_user():
    assert HOME == expand_path('~')


def test_envvar():
    ENVVAR = 'SAFE_TEST_EXPAND_PATH_VAR'
    os.environ[ENVVAR] = '/foo'
    try:
        assert '/foo' == expand_path('$%s' % ENVVAR)
    finally:
        del os.environ[ENVVAR]


def test_nested():
    ENVVAR = 'SAFE_TEST_EXPAND_PATH_VAR'
    os.environ[ENVVAR] = '~'
    try:
        assert HOME == expand_path('$%s' % ENVVAR)
    finally:
        del os.environ[ENVVAR]
