# -*- coding: utf-8 -*-
"""
Shell command.

:author: Joe Joyce <joe@decafjoe.com>
:copyright: Copyright (c) Joe Joyce and contributors, 2016-2018.
:license: BSD
"""
import subprocess

from clik_shell import DefaultShell, exclude_from_shell

from safe.app import safe
from safe.util import get_executable


CLEAR_EXECUTABLE = get_executable('clear')


class Shell(DefaultShell):
    """Shell subclass that adds the ``clear`` command if available."""

    intro = '\nWelcome to the safe shell. Enter ? for a list of commands.\n'

    def __init__(self):
        """Instantiate the command shell."""
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
