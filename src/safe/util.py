# -*- coding: utf-8 -*-
"""
No project is complete without a utility module.

:author: Joe Joyce <joe@decafjoe.com>
:copyright: Copyright (c) Joe Joyce and contributors, 2016-2017.
:license: BSD
"""
import contextlib
import os
import shutil
import stat
import tempfile

from safe.compat import input


def expand_path(path):
    """
    Return absolute path, with variables and ``~`` expanded.

    :param str path: Path, possibly with variables and ``~``.
    :return: Absolute path with special sequences expanded.
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
    tmp = tempfile.mkdtemp()
    os.chmod(tmp, stat.S_IRWXU)
    try:
        yield tmp
    finally:
        shutil.rmtree(tmp)
