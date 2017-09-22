# -*- coding: utf-8 -*-
"""


:author: Joe Joyce <joe@decafjoe.com>
:copyright: Copyright (c) Joe Joyce and contributors, 2016-2017.
:license: BSD
"""
from safe.app import safe


@safe(name='set')
def set_():
    """Set account-related values."""
    yield
