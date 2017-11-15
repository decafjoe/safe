# -*- coding: utf-8 -*-
"""
Tests for :func:`safe.util.temporary_directory`.

:author: Joe Joyce <joe@decafjoe.com>
:copyright: Copyright (c) Joe Joyce and contributors, 2016-2017.
:license: BSD
"""
import os
import stat

from safe.util import temporary_directory


def test():
    """Check permissions then deletion of temporary directory."""
    with temporary_directory() as tmp:
        assert stat.S_IRWXU | stat.S_IFDIR == os.stat(tmp).st_mode
    assert not os.path.exists(tmp)
