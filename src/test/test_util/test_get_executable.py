# -*- coding: utf-8 -*-
"""
Tests for :func:`safe.util.get_executable`.

:author: Joe Joyce <joe@decafjoe.com>
:copyright: Copyright (c) Joe Joyce and contributors, 2016-2018.
:license: BSD
"""
import subprocess

from safe.util import get_executable


def test_missing():
    """Check that ``None`` is returned for missing executables."""
    assert get_executable('this_is_not_a_real_executable_i_hope') is None


def test_ls():
    """Check that ``get_executable('ls')`` matches ``which ls``."""
    for line in subprocess.check_output(('which', 'ls')).splitlines():
        line = line.decode('utf-8').strip()
        if line and line.lstrip()[0] == '/':
            expected = line.strip()
            break
    assert expected == get_executable('ls')
