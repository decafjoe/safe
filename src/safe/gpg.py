# -*- coding: utf-8 -*-
"""
Facilities for interacting with GPG encrypted files.

:author: Joe Joyce <joe@decafjoe.com>
:copyright: Copyright (c) Joe Joyce and contributors, 2016-2018.
:license: BSD
"""
import os
import re
import shutil
import subprocess

from safe.util import get_executable, Subprocess, temporary_directory


#: Name of the cipher to use if unspecified in :meth:`GPGFile.save`.
#:
#: :type: :class:`str`
PREFERRED_CIPHER = 'aes256'


class GPGError(Exception):
    """Raised for errors from this module."""

    def __init__(self, message, stdout, stderr):
        """
        Instantiate the error.

        :param str message: Short message describing the error
        :param stdout: Standard output related to the error
        :type stdout: :class:`str` or ``None``
        :param stderr: Standard error related to the error
        :type stderr: :class:`str` or ``None``
        """
        super(GPGError, self).__init__(message)

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


def get_gpg_executable():
    """
    Return GPG executable, raising a :exc:`GPGError` if not found.

    This will first look for an executable named ``gpg2``, returning it
    immediately if found. If ``gpg2`` does not exist but ``gpg`` does, this
    function runs ``gpg --version`` to check the version. If version 2, the
    absolute path to the executable is returned.

    Failure to find a GPG2 executable results in a :exc:`GPGError` being
    raised.

    :raise: :exc:`GPGError` if GPG executable is not found
    :return: Absolute path to the GPG executable
    :rtype: :class:`str`
    """
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
    """Convenience class for running GPG commands."""

    #: Absolute path to the GPG executable.
    #:
    #: This is populated the first time a :class:`GPGSubprocess` is
    #: instantiated and is subsequently reused.
    #:
    #: :type: ``None`` until populated with a :class:`str` on :meth:`__init__`
    _gpg = None

    def __init__(self, command):
        """
        Instantiate the subprocess.

        :param command: Arguments to pass to GPG
        :type command: :func:`tuple` of arguments, *not* including ``gpg``
                       itself at the beginning
        """
        if self.__class__._gpg is None:
            self.__class__._gpg = get_gpg_executable()

        cmd = (self._gpg,) + command
        pipe = subprocess.PIPE
        kwargs = dict(stdin=pipe, stdout=pipe, stderr=pipe)
        super(GPGSubprocess, self).__init__(cmd, **kwargs)


class GPGFile(object):
    """Manage decryption and encryption of a GPG file."""

    #: Regex matching the keyid output string from ``gpg
    #: --list-packets``.
    #:
    #: :type: :func:`re.compile`
    KEYID_RE = re.compile(r'keyid (?P<keyid>[0-9A-F]+)')

    # These are defined here so we can reference them in the internal
    # documentation in doc/development/internals/gpg.rst.
    _homedir = None
    _keyid = None
    _password = None
    _path = None
    _symmetric = None

    def __init__(self, path):
        """
        Instantiate the file wrapper.

        :param str path: Path to the GPG encrypted file
        :raise: :exc:`GPGError` if file cannot be read
        """
        #: Home directory to use for GnuPG calls (i.e. the ``--homedir``
        #: argument). Defaults to ~/.gnupg. This attribute exists to
        #: allow tests to tweak the GnuPG environment while running,
        #: and is not otherwise used.
        #:
        #: :type: :class:`str`
        self._homedir = os.path.join(os.path.expanduser('~'), '.gnupg')

        #: Keyid to which the file was encrypted. Populated when
        #: :meth:`decrypt_to` is called.
        #:
        #: :type: :class:`str` or ``None`` (if file is symmetrically
        #:        encrypted)
        self._keyid = None

        #: Password with which file was encryted. Populated when
        #: :meth:`decrypt_to` is called.
        #:
        #: :type: :class:`str` or ``None`` (if file is asymmetrically
        #:        encrypted)
        self._password = None

        #: Path to the encrypted file.
        #:
        #: :type: :class:`str`
        self._path = path

        #: Boolean indicating whether the file is symmetrically
        #: encrypted. If false, the file is asymmetrically encrypted.
        #:
        #: :type: :class:`bool`
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
                error_msg = 'failed to extract keyid from packets'
                match = self.KEYID_RE.search(line)
                if not match:
                    raise GPGError(error_msg, stdout, stderr)
                keyid = match.groupdict()['keyid']
                if re.search('^0+$', keyid):
                    raise GPGError(error_msg, stdout, stderr)
                self._keyid = keyid
                break

        if self._symmetric is None:
            msg = 'did not find encryption type packet in file (are you ' \
                  'sure this is a gpg file?)'
            raise GPGError(msg, stdout, stderr)

    @property
    def symmetric(self):
        """If true, file is encrypted symmetrically (i.e. with a password)."""
        return self._symmetric

    def decrypt_to(self, path, password=None):
        """
        Decrypt file to ``path`` using ``password``.

        If decryption is successful, this will cache the password/keyid for
        use in subsequent calls to :meth:`save`.

        :param str path: Path to which to decrypt file
        :param password: Password for file, if encrypted symmetrically
        :type password: :class:`str` if file is symmetrically encrypted else
                        ``None``
        :raise: :exc:`GPGError` if decryption fails
        :rtype: ``None``
        """
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
        """
        Save plaintext file ``source`` back to the original path, encrypted.

        :meth:`decrypt_to` **must be called before calling this method.**
        Certain values needed by this method are cached when a file is
        decrypted. (Namely, password for symmetrically encrypted files and
        keyid for asymmetrically encrypted files.)

        :param str source: Path to file to save
        :param str cipher: Cipher to use for encryption (defaults to
                           :data:`PREFERRED_CIPHER`)
        :raise: :exc:`GPGError` if encryption fails (original encrypted file is
                left untouched)
        :rtype: ``None``
        """
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
