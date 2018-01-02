# -*- coding: utf-8 -*-
"""
No project is complete without a utility module.

:author: Joe Joyce <joe@decafjoe.com>
:copyright: Copyright (c) Joe Joyce and contributors, 2016-2018.
:license: BSD
"""
import contextlib
import os
import shutil
import stat
import subprocess
import tempfile

from safe.compat import input


def expand_path(path):
    """
    Return absolute path, with variables and ``~`` expanded.

    :param str path: Path, possibly with variables and ``~``
    :return: Absolute path with special sequences expanded
    :rtype: str
    """
    return os.path.abspath(os.path.expanduser(os.path.expandvars(path)))


def get_executable(name):
    """
    Return the full path to executable named ``name``, if it exists.

    :param str name: Name of the executable to find
    :return: Full path to the executable or ``None``
    :rtype: :class:`str` or ``None``
    """
    directories = filter(None, os.environ.get('PATH', '').split(os.pathsep))
    for directory in directories:
        path = os.path.join(directory.strip('"'), name)
        if os.path.isfile(path) and os.access(path, os.X_OK):
            return path


def prompt_bool(prompt, default=False):
    """
    Prompt user for a yes or no answer and return the result as a boolean.

    :param str prompt: Prompt. ``' [y/n] '`` will be appended to this value
    :param bool default: Default value if user enters nothing
    :return: Boolean indicating user's choice
    :rtype: :class:`bool`
    """
    if default is True:
        choices = ' [Y/n] '
        flip_if = 'n'
    else:
        choices = ' [y/N] '
        flip_if = 'y'
    response = input(prompt + choices)
    if response and response[0].lower() == flip_if:
        return not default
    return default


@contextlib.contextmanager
def temporary_directory():
    """
    Context manager that creates a temporary directory for use in the body.

    Example::

       with temporary_directory() as tmp:
           # do stuff with tmp

    The temporary directory permissions are set to 0700 before handing control
    over to the body.
    """
    tmp = tempfile.mkdtemp()
    os.chmod(tmp, stat.S_IRWXU)
    try:
        yield tmp
    finally:
        shutil.rmtree(tmp)


class Subprocess(subprocess.Popen):
    """Subclass whose :meth:`communicate` method turns bytes into strings."""

    def communicate(self, stdin=None):
        """
        Override parent to make sure bytes are decoded into strings.

        :param stdin: Data to send to stdin
        :type stdin: :class:`str` or ``None``
        :return: 2-tuple, ``(stdout, stderr)``
        :rtype: 2-:func:`tuple`
        """
        if stdin is not None:
            stdin = stdin.encode('utf-8')
        stdout, stderr = super(Subprocess, self).communicate(stdin)
        if stdout is not None:
            stdout = stdout.decode('utf-8')
        if stderr is not None:
            stderr = stderr.decode('utf-8')
        return stdout, stderr
