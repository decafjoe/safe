# -*- coding: utf-8 -*-
"""
Tests for :class:`safe.util.Subprocess`.

:author: Joe Joyce <joe@decafjoe.com>
:copyright: Copyright (c) Joe Joyce and contributors, 2016-2019.
:license: BSD
"""
import subprocess

from safe.util import Subprocess


PIPE = subprocess.PIPE


def test_stdout():
    """Check that stdout is returned as a string."""
    process = Subprocess(('printf', 'hai'), stdout=PIPE)
    stdout, stderr = process.communicate()
    assert stdout == 'hai'
    assert stderr is None


def test_stderr():
    """Check that stderr is returned as a string."""
    process = Subprocess('printf hai >&2', stderr=PIPE, shell=True)
    stdout, stderr = process.communicate()
    assert stdout is None
    assert stderr == 'hai'


def test_stdin():
    """Check that stdin accepts a string."""
    process = Subprocess(('cat', '-'), stdin=PIPE, stdout=PIPE)
    stdout, stderr = process.communicate(stdin='hai')
    assert stdout == 'hai'
    assert stderr is None
