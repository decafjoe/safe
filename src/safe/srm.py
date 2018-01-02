# -*- coding: utf-8 -*-
"""
Secure file deletion utility.

:author: Joe Joyce <joe@decafjoe.com>
:copyright: Copyright (c) Joe Joyce and contributors, 2016-2018.
:license: BSD
"""
import os

from safe.util import get_executable, Subprocess


#: Value to pass to ``--iterations`` argument of ``shred``.
#:
#: :type: :class:`int`:
SHRED_ITERATIONS = 35


class SecureDeleteError(Exception):
    """Raised when there is a problem securely deleting a file."""

    def __init__(self, message, stdout, stderr):
        """
        Instantiate the error.

        :param str message: Short message describing the error
        :param stdout: Standard output related to the error
        :type stdout: :class:`str` or ``None``
        :param stderr: Standard error related to the error
        :type stderr: :class:`str` or ``None``
        """
        super(SecureDeleteError, self).__init__(message)

        #: Short message describing the error.
        #:
        #: :type: :class:`str`
        self.message = message

        #: Standard out associated with the error.
        #:
        #: :type: :class:`str` or ``None``
        self.stdout = stdout

        #: Standard error associated with the error.
        #:
        #: :type: :class:`str` or ``None``
        self.stderr = stderr


def secure_delete(path):
    """
    Securely delete file at ``path``.

    :param str path: Path of file to delete
    :raise: :exc:`SecureDeleteError` if there are no secure deletion utilities
            found on the machine, or if the secure deletion utility returns
            a non-zero exit code
    :rtype: ``None``
    """
    srm = get_executable('srm')
    if srm is not None:
        process = Subprocess((srm, path))
        stdout, stderr = process.communicate()
        if process.returncode:
            msg = 'srm returned non-zero exit code: %s' % process.returncode
            raise SecureDeleteError(msg, stdout, stderr)
        return

    shred = get_executable('shred')
    if shred is not None:
        cmd = (shred, '--iterations', str(SHRED_ITERATIONS), path)
        process = Subprocess(cmd)
        stdout, stderr = process.communicate()
        if process.returncode:
            msg = 'shred returned non-zero exit code: %s' % process.returncode
            raise SecureDeleteError(msg, stdout, stderr)
        os.unlink(path)
        return

    msg = 'no secure delete programs were found'
    raise SecureDeleteError(msg, None, None)
