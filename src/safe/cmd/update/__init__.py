# -*- coding: utf-8 -*-
"""
Update object command group.

:author: Joe Joyce <joe@decafjoe.com>
:copyright: Copyright (c) Joe Joyce and contributors, 2016-2018.
:license: BSD
"""
from safe.app import safe


@safe(alias='up')
def update():
    """Update objects in the database."""
    yield
