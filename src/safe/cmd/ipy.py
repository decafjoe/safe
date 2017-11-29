# -*- coding: utf-8 -*-
"""
IPython shell.

:author: Joe Joyce <joe@decafjoe.com>
:copyright: Copyright (c) Joe Joyce and contributors, 2016-2017.
:license: BSD
"""
from safe.app import allow_missing_file, safe

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

        from clik import args, g
        from safe.model import Account, Alias, Code, Password, Policy, \
            Question

        IPython.embed()
