# -*- coding: utf-8 -*-
"""
IPython shell.

:author: Joe Joyce <joe@decafjoe.com>
:copyright: Copyright (c) Joe Joyce and contributors, 2016-2018.
:license: BSD
"""
from safe.app import safe

try:
    import IPython
    ipython_available = True
except ImportError:
    ipython_available = False


ENABLE_IPYTHON = False


if ENABLE_IPYTHON and ipython_available:
    @safe
    def ipy():
        """Open an IPython shell."""
        yield

        from clik import args, g  # noqa: F401
        from safe.model import Account, Alias, Code, Password  # noqa: F401
        from safe.model import Policy, Question  # noqa: F401

        IPython.embed()
