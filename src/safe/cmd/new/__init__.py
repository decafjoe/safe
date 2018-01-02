# -*- coding: utf-8 -*-
"""
New object command group.

:author: Joe Joyce <joe@decafjoe.com>
:copyright: Copyright (c) Joe Joyce and contributors, 2016-2018.
:license: BSD
"""
from safe.app import safe


@safe
def new():
    """Add objects to the database."""
    yield
