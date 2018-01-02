# -*- coding: utf-8 -*-
"""
Drop object command group.

:author: Joe Joyce <joe@decafjoe.com>
:copyright: Copyright (c) Joe Joyce and contributors, 2016-2018.
:license: BSD
"""
from safe.app import safe


@safe(alias='rm')
def drop():
    """Drop objects from the database."""
    yield
