# -*- coding: utf-8 -*-
"""


:author: Joe Joyce <joe@decafjoe.com>
:copyright: Copyright (c) Joe Joyce and contributors, 2016-2017.
:license: BSD
"""
import subprocess

from clik_shell import DefaultShell, exclude_from_shell

from safe.app import safe
from safe.util import get_executable


CLEAR_EXECUTABLE = get_executable('clear')


class Shell(DefaultShell):
    intro = '\nWelcome to the safe shell. Enter ? for a list of commands.\n'

    def __init__(self):
        super(Shell, self).__init__(safe)

    if CLEAR_EXECUTABLE is not None:
        def do_clear(self, _):
            """Clear the screen."""
            subprocess.call(CLEAR_EXECUTABLE)


@exclude_from_shell
@safe(alias='sh')
def shell():
    """Interactive command shell for safe."""
    yield
    Shell().cmdloop()
