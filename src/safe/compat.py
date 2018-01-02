# -*- coding: utf-8 -*-
"""
Python compatibility helpers.

:author: Joe Joyce <joe@decafjoe.com>
:copyright: Copyright (c) Joe Joyce and contributors, 2016-2018.
:license: BSD
"""
try:
    input = raw_input
except NameError:
    try:
        input = __builtins__['input']
    except TypeError:
        input = __builtins__.input
