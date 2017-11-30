# -*- coding: utf-8 -*-
"""
Tests that make sure all commands successfully complete when called with -h.

:author: Joe Joyce <joe@decafjoe.com>
:copyright: Copyright (c) Joe Joyce and contributors, 2016-2017.
:license: BSD
"""
import io
import sys

import pytest

from clik.compat import PY2

from safe.app import safe


def setup():
    import safe.cmd


@pytest.mark.parametrize('argv', [
    [],
    ['gen'],
    ['init'],
    ['new'],
    ['new', 'account'],
    ['shell'],
    ['sh'],
    ['update'],
    ['update', 'account'],
])
def test(argv):
    orig_stdout, orig_stderr = sys.stdout, sys.stderr
    sys.stdout, sys.stderr = io.StringIO(), io.StringIO()
    if PY2:
        sys.stdout, sys.stderr = io.BytesIO(), io.BytesIO()
    try:
        safe.main(['safe'] + argv + ['-h'], lambda *args, **kwargs: None)
    finally:
        sys.stdout, sys.stderr = orig_stdout, orig_stderr
