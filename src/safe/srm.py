# -*- coding: utf-8 -*-
"""
Secure file deletion utility.

:author: Joe Joyce <joe@decafjoe.com>
:copyright: Copyright (c) Joe Joyce and contributors, 2016-2017.
:license: BSD
"""
import subprocess

from safe.util import get_executable


SHRED_ITERATIONS = 35


SRM_EXECUTABLE = get_executable('srm')
SRM_COMMAND = (SRM_EXECUTABLE,)
if SRM_EXECUTABLE is None:
    SRM_EXECUTABLE = get_executable('shred')
    SRM_COMMAND = (SRM_EXECUTABLE, '--iterations', '35')


class SRM(subprocess.Popen):
    def __init__(self, path):
        if SRM_EXECUTABLE is not None:
            command = SRM_COMMAND + (path,)
            pipe = subprocess.PIPE
            super(SRM, self).__init__(command, stdout=pipe, stderr=pipe)

    def communicate(self):
        stdout, stderr = super(SRM, self).communicate()
        if stdout:
            stdout = stdout.decode('utf-8')
        if stderr:
            stderr = stderr.decode('utf-8')
        return stdout, stderr
