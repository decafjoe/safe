# -*- coding: utf-8 -*-
"""
Tests that make sure all commands successfully complete when called with -h.

:author: Joe Joyce <joe@decafjoe.com>
:copyright: Copyright (c) Joe Joyce and contributors, 2016-2019.
:license: BSD
"""
import io
import sys

import pytest
from clik.compat import PY2

from safe.app import safe


def setup():
    """Make sure all commands are imported."""
    import safe.cmd  # noqa: F401


@pytest.mark.parametrize('argv', [
    [],
    ['clipboard'],
    ['drop'],
    ['drop', 'account'],
    ['drop', 'policy'],
    ['gen'],
    ['gen', 'per-policy'],
    ['init'],
    ['list'],
    ['new'],
    ['new', 'account'],
    ['new', 'policy'],
    ['shell'],
    ['sh'],
    ['update'],
    ['update', 'account'],
    ['update', 'policy'],
])
def test(argv):
    """Check that all commands can be run with ``-h``."""
    orig_stdout, orig_stderr = sys.stdout, sys.stderr
    sys.stdout, sys.stderr = io.StringIO(), io.StringIO()
    if PY2:
        sys.stdout, sys.stderr = io.BytesIO(), io.BytesIO()
    try:
        safe.main(['safe'] + argv + ['-h'], lambda *args, **kwargs: None)
    finally:
        sys.stdout, sys.stderr = orig_stdout, orig_stderr
