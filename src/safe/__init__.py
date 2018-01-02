# -*- coding: utf-8 -*-
"""
Entry point and top-level package information.

:author: Joe Joyce <joe@decafjoe.com>
:copyright: Copyright (c) Joe Joyce and contributors, 2016-2018.
:license: BSD
"""
import sys


#: Version of the program.
#:
#: :type: :class:`str`
__version__ = '0.6.2'


def main(argv=None, exit=sys.exit):
    """Entry point for the program."""
    import safe.app
    import safe.cmd
    return safe.app.safe.main(argv, exit)
