# -*- coding: utf-8 -*-
"""


:author: Joe Joyce <joe@decafjoe.com>
:copyright: Copyright (c) Joe Joyce and contributors, 2016-2017.
:license: BSD
"""
import os
import re
import shutil
import subprocess
import tempfile

from safe.util import get_executable, temporary_directory, Subprocess


PREFERRED_CIPHER = 'aes256'


class GPGError(Exception):
    def __init__(self, message, stdout, stderr):
        super(GPGError, self).__init__(message)
        self.message = message
        self.stdout = stdout
        self.stderr = stderr


def get_gpg_executable():
    rv = get_executable('gpg2')
    if rv is not None:
        return rv

    rv = get_executable('gpg')
    if rv is None:
        msg = 'neither gpg2 nor gpg executables were found'
        raise GPGError(msg, None, None)

    process = Subprocess((rv, '--version'), stdout=subprocess.PIPE)
    stdout, stderr = process.communicate()
    if process.returncode:
        msg = '`gpg --version` exited non-zero: %s' % process.returncode
        raise GPGError(msg, stdout, stderr)

    regex = re.compile(r'^gpg[^\n]+\s+((?P<major>\d+)\.\d+\.\d+).+', re.DOTALL)
    match = regex.search(stdout)
    if not match:
        msg = 'could not extract version from `gpg --version`'
        raise GPGError(msg, stdout, stderr)

    major_version = match.groupdict()['major']
    if major_version != '2':
        msg = 'safe requires gpg version 2, found version: %s' % major_version
        raise GPGError(msg, stdout, stderr)

    return rv


class GPGSubprocess(Subprocess):
    _gpg = None

    def __init__(self, command):
        if self.__class__._gpg is None:
            self.__class__._gpg = get_gpg_executable()

        cmd = (self._gpg,) + command
        pipe = subprocess.PIPE
        kwargs = dict(stdin=pipe, stdout=pipe, stderr=pipe)
        super(GPGSubprocess, self).__init__(cmd, **kwargs)


class GPGFile(object):
    KEYID_RE = re.compile(r'keyid (?P<keyid>[0-9A-F]+)')

    def __init__(self, path):
        self._homedir = os.path.join(os.path.expanduser('~'), '.gnupg')
        self._keyid = None
        self._password = None
        self._path = path
        self._symmetric = None

        with temporary_directory() as tmp:
            command = (
                '--batch',
                '--homedir', tmp,
                '--passphrase', '',
                '--quiet',
                '--list-packets',
                path,
            )
            process = GPGSubprocess(command)
            stdout, stderr = process.communicate()

        for line in stdout.splitlines():
            if line.startswith(':symkey'):
                self._symmetric = True
                break
            elif line.startswith(':pubkey'):
                self._symmetric = False
                match = self.KEYID_RE.search(line)
                if not match:
                    msg = 'failed to extract keyid from packets'
                    raise GPGError(msg, stdout, stderr)
                self._keyid = match.groupdict()['keyid']
                break

        if self._symmetric is None:
            msg = 'did not find encryption type packet in file (are you ' \
                  'sure this is a gpg file?)'
            raise GPGError(msg, stdout, stderr)

    @property
    def symmetric(self):
        return self._symmetric

    def decrypt_to(self, path, password=None):
        if self.symmetric and password is None:
            raise Exception('password required when symmetrically encrypted')
        command = (
            '--batch',
            '--homedir', self._homedir,
            '--output', path,
            '--quiet',
        )
        if self.symmetric:
            command += ('--passphrase-fd', '0')
        command += ('--decrypt', self._path)
        process = GPGSubprocess(command)
        stdout, stderr = process.communicate(password)
        if process.returncode:
            raise GPGError('failed to decrypt file', stdout, stderr)
        self._password = password

    def save(self, source, cipher=PREFERRED_CIPHER):
        with temporary_directory() as tmp:
            tmp_path = os.path.join(tmp, 'f')
            command = (
                '--armor',
                '--batch',
                '--cipher-algo', cipher,
                '--homedir', self._homedir,
                '--output', tmp_path,
                '--quiet',
            )
            if self.symmetric:
                command += ('--passphrase-fd', '0', '--symmetric')
            else:
                command += ('--recipient', self._keyid, '--encrypt')
            command += (source,)
            process = GPGSubprocess(command)
            stdout, stderr = process.communicate(self._password)
            if process.returncode:
                raise GPGError('failed to re-encrypt file', stdout, stderr)
            shutil.move(tmp_path, self._path)
