# -*- coding: utf-8 -*-
"""
Python compatibility helpers.

:author: Joe Joyce <joe@decafjoe.com>
:copyright: Copyright (c) Joe Joyce and contributors, 2016-2017.
:license: BSD
"""
try:
    input = raw_input
except NameError:
    input = __builtins__['input']
