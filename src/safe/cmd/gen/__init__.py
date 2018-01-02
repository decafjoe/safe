# -*- coding: utf-8 -*-
"""
Secret generation utility command.

:author: Joe Joyce <joe@decafjoe.com>
:copyright: Copyright (c) Joe Joyce and contributors, 2016-2018.
:license: BSD
"""
from safe.app import safe


@safe
def gen():
    """Generate secrets to stdout."""
    yield
