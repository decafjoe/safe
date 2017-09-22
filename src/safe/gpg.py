# -*- coding: utf-8 -*-
"""


:author: Joe Joyce <joe@decafjoe.com>
:copyright: Copyright (c) Joe Joyce and contributors, 2016-2017.
:license: BSD
"""
import subprocess

from safe.util import get_executable


GPG_EXECUTABLE_NAME = 'gpg2'
GPG_EXECUTABLE = get_executable(GPG_EXECUTABLE_NAME)
PREFERRED_CIPHER = 'aes256'


class GPG(subprocess.Popen):
    def __init__(self, command, capture=False):
        pipe = subprocess.PIPE
        kwargs = dict(stdin=pipe)
        if capture:
            kwargs.update(dict(stdout=pipe, stderr=pipe))
        super(GPG, self).__init__((GPG_EXECUTABLE,) + command, **kwargs)

    def communicate(self, stdin=None):
        if stdin is not None:
            stdin = stdin.encode('utf-8')
        stdout, stderr = super(GPG, self).communicate(stdin)
        if stdout:
            stdout = stdout.decode('utf-8')
        if stderr:
            stderr = stderr.decode('utf-8')
        return stdout, stderr
