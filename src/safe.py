# -*- coding: utf-8 -*-
"""
Safe -- a command-line application for storing your secrets.

:author: Joe Strickler <joe@decafjoe.com>
:copyright: Joe Strickler, 2016. All rights reserved.
:license: Proprietary
"""
import binascii
import datetime
import functools
import getpass
import hashlib
import hmac
import itertools
import json
import operator
import os
import re
import shutil
import struct
import sys
import tempfile
import time
import warnings

import arrow
import pexpect
import sqlalchemy
import sqlalchemy.orm
import sqlalchemy.ext.declarative
import sqlalchemy_utils

from clik import app, args, g, parser, subcommand

from os import urandom as random_bytes

try:
    from cryptography.fernet import Fernet as CryptographyFernet, \
        InvalidToken as CryptographyInvalidToken

    #: Boolean indicating whether the `cryptography
    #: <https://cryptography.io/en/latest/>`_ package is installed.
    #:
    #: :type: :class:`bool`
    CRYPTOGRAPHY_INSTALLED = True
except ImportError:  # pragma: no cover
    CRYPTOGRAPHY_INSTALLED = False

try:
    with warnings.catch_warnings():
        warnings.simplefilter('ignore')
        from nacl.encoding import Base64Encoder as NaClBase64Encoder
        from nacl.exceptions import CryptoError as NaClCryptoError
        from nacl.secret import SecretBox as NaClSecretBox

        # F811: redefinition of unused 'random_bytes'
        # This is how it's supposed to work: by default we use the
        # OS's urandom function for random bytes. If PyNaCl is
        # installed, we redefine random_bytes to NaCl's random,
        # with the assumption that it's at least as good or better
        # than urandom.
        from nacl.utils import random as random_bytes  # noqa: F811

    #: Boolean indicating whether the `PyNaCl
    #: <https://pynacl.readthedocs.org/en/latest/>`_ package is installed.
    #:
    #: :type: :class:`bool`
    NACL_INSTALLED = True
except ImportError:  # pragma: no cover
    NACL_INSTALLED = False


#: Indicates the version of the program
#:
#: :type: :class:`str`
__version__ = '0.2.0'


# =============================================================================
# ----- Base Exceptions -------------------------------------------------------
# =============================================================================

class SafeError(Exception):
    """Base class for all exceptions raised from this module."""


class SafeCryptographyError(SafeError):
    """Base class for crypto-related errors."""


# =============================================================================
# ----- JSON+Datetime ---------------------------------------------------------
# =============================================================================

#: Regular expression matching the format for JSON dates.
#:
#: :type: :func:`re <re.compile>`
date_re = re.compile(r'\\/Date\((-?\d+)\)\\/')


def dump_json(obj, fp=None, **kwargs):
    """
    Dump JSON to a string or file, using :class:`JSONDatetimeEncoder`.

    ``obj`` and ``fp`` are handled as documented below. The rest of the
    ``**kwargs`` are passed straight through to the underlying :mod:`json`
    dump function.

    :param obj: Object to dump to JSON.
    :type obj: JSON-encodable (including :class:`datetime.datetime`)
    :param fp: If :data:`None`, this calls :func:`json.dumps` and returns the
               result. If ``fp`` is a string, it is interpreted as a file path
               to which the data will be written. If ``fp`` is a file-like
               object, this calls :func:`json.dump` with ``obj`` and ``fp``.
               Defaults to :data:`None`.
    :type fp: :data:`None` or :class:`str` or file-like object
    :return: JSON-encoded ``obj`` if dumping to a string.
    :rtype: :class:`str` if ``fp`` is :data:`None`, else :data:`None`.
    """
    kwargs.setdefault('cls', JSONDatetimeEncoder)
    if fp is None:
        return json.dumps(obj, **kwargs)
    elif isinstance(fp, basestring):
        fd, tmp_fp = tempfile.mkstemp()
        try:
            f = os.fdopen(fd, 'w')
            try:
                dump_json(obj, f)
            finally:
                f.close()
            os.rename(tmp_fp, fp)
        except:
            try:
                os.close(fd)
            except OSError:
                pass
            os.unlink(tmp_fp)
            raise
    else:
        return json.dump(obj, fp, **kwargs)


def load_json(str_or_fp, **kwargs):
    """
    Load JSON from string or file, using :class:`JSONDatetimeDecoder`.

    ``str_or_fp`` is handled as described below. The rest of the ``**kwargs``
    are passed straight through to the underlying :mod:`json` load function.

    :param str_or_fp: String or file-like object from which to load.
    :type str_or_fp: :class:`str` or file-like object
    :return: Decoded JSON object.
    :rtype: JSON-encodable type (including :class:`datetime.datetime`)
    """
    kwargs.setdefault('cls', JSONDatetimeDecoder)
    if isinstance(str_or_fp, basestring):
        return json.loads(str_or_fp, **kwargs)
    return json.load(str_or_fp, **kwargs)


class JSONDatetimeDecoder(json.JSONDecoder):
    """Datetime-aware JSON decoder."""

    def decode(self, s):
        """
        Override method to support datetime-encoded values.

        Uses :meth:`decode_date` to handle datetime-encoded values.

        .. seealso:: Superclass documentation: :meth:`json.JSONDecoder.decode`
        """
        return self.decode_date(super(JSONDatetimeDecoder, self).decode(s))

    def decode_date(self, value):
        """
        Datetime-aware decoding method.

        If the string value matches the datetime format, it is decoded. Lists
        and dictionaries are examined recursively for datetime formatted
        values. All other values are returned as-is.

        :param value: Value to decode.
        :type value: JSON-encodable type
        :return: ``value``, with datetime-formatted strings converted to
                 actual :class:`datetime.datetime` objects.
        :rtype: JSON-encodable type (including :class:`datetime.datetime`)
        """
        decode = self.decode_date
        if isinstance(value, basestring):
            match = date_re.search(value)
            if match:
                timestamp = int(match.groups()[0])
                return datetime.datetime.fromtimestamp(timestamp / 1000)
        elif isinstance(value, list):
            return [decode(v) for v in value]
        elif isinstance(value, dict):
            return dict([(decode(k), decode(v)) for k, v in value.iteritems()])
        return value


class JSONDatetimeEncoder(json.JSONEncoder):
    """
    Datetime-aware JSON encoder.

    This class overrides the :meth:`encode` and :meth:`iterencode` methods to
    support decoding datetime-encoded strings. When one of these methods is
    called, the supplied object is encoded as follows.

    #. The object is searched recursively for :class:`datetime.datetime`
       keys in dictionaries. Those keys are replaced with datetime-encoded
       strings. (See :meth:`_replace_datetime`.) This is necessary because
       the parent encoding routine will choke on datetime keys.
    #. The object is encoded. For values that the parent class can't encode
       (i.e. datetime objects), it calls :meth:`default`, which will
       datetime-encode :class:`datetime.datetime` objects.
    #. The dictionary keys that were swapped in step 1 are restored back to
       their original objects. (See :meth:`_restore_datetime`.)
    """

    def _encode_date(self, date):
        """
        Encode ``date`` as datetime-formatted string.

        :param datetime.datetime date: Datetime to encode.
        :return: String that will be interpreted as a datetime by
                 :class:`JSONDatetimeDecoder`.
        :rtype: str
        """
        return '\/Date(%i)\/' % int(time.mktime(date.timetuple()) * 1000)

    def _replace_datetime(self, obj):
        r"""
        Replace datetime dict keys with datetime-encoded strings.

        As an example (pseudo-REPL)::

            >>> date = datetime.datetime(2016, 1, 1)
            >>> d = {date: 'foo'}
            >>> changes = JSONDatetimeEncoder()._replace_datetime(d)
            [(d, date, '\/Date(1451624400000)\/')]
            >>> d
            {'\/Date(1451624400000)\/': 'foo'}

        Note that this modifies ``obj`` in place rather than making a copy.
        The return value represents the changes that were made, and can be
        passed to :meth:`_restore_datetime` (along with ``obj``) to
        undo the changes made by this method.

        If ``obj`` is a list or a dictionary, it is recursively searched for
        dictionaries containing :class:`datetime.datetime` keys.

        :param obj: Object for which to replace datetime dict keys.
        :type obj: JSON-encodable (including :class:`datetime.datetime`)
        :return: List of 3-tuples representing changes:
                 ``[(obj, original_key, substitute_key), ...]``
        :rtype: list
        """
        rv = []
        if isinstance(obj, dict):
            for key, value in obj.items():
                if isinstance(key, datetime.datetime):
                    new_key = self._encode_date(key)
                    rv.append((obj, new_key, key))
                    obj[new_key] = obj[key]
                    del obj[key]
                rv.extend(self._replace_datetime(value))
        elif isinstance(obj, list):
            for value in obj:
                rv.extend(self._replace_datetime(value))
        return rv

    def _restore_datetime(self, obj, changes):
        """
        Restore keys altered by :meth:`_replace_datetime`.

        Continuing the example from :meth:`_replace_datetime`::

            >>> JSONDatetimeEncoder()._restore_datetime(d, changes)
            >>> d
            {date: 'foo'}

        :param obj: Object for which to restore datetime dict keys.
        :type obj: JSON-encodable
        :param changes: List of changes made by :meth:`_replace_datetime`.
        :type changes: :class:`list`
                       ``[(obj, original_key, substitute_key), ...]``
        :rtype: None
        """
        for obj, new_key, old_key in changes:
            obj[old_key] = obj[new_key]
            del obj[new_key]

    def default(self, obj):
        """
        Override method to support datetime-encoded values.

        This is called when the parent encoder is unable to encode a value.
        If ``obj`` is a :class:`datetime.datetime`, we datetime-encode it and
        return that string. If it's anything else, we call the parent method,
        which will bail out.

        .. seealso:: Superclass documentation: :meth:`json.JSONEncoder.default`
        """
        if isinstance(obj, datetime.datetime):
            return self._encode_date(obj)
        return super(JSONDatetimeEncoder, self).default(obj)

    def encode(self, obj, *args, **kwargs):
        """
        Override method to support datetime-encoded values.

        ``obj`` is encoded as documented by :class:`JSONDatetimeEncoder`.
        The remaining ``*args`` and ``**kwargs`` are passed as-is to the
        parent method.

        .. seealso:: Superclass documentation: :meth:`json.JSONEncoder.encode`
        """
        superclass = super(JSONDatetimeEncoder, self)
        replaced = self._replace_datetime(obj)
        try:
            return superclass.encode(obj, *args, **kwargs)
        finally:
            self._restore_datetime(obj, replaced)

    def iterencode(self, obj, *args, **kwargs):
        """
        Override method to support datetime-encoded values.

        ``obj`` is encoded as documented by :class:`JSONDatetimeEncoder`.
        The remaining ``*args`` and ``**kwargs`` are passed as-is to the
        parent method.

        .. seealso::

           Superclass documentation: :meth:`json.JSONEncoder.iterencode`

        """
        superclass = super(JSONDatetimeEncoder, self)
        replaced = self._replace_datetime(obj)
        try:
            for chunk in superclass.iterencode(obj, *args, **kwargs):
                yield chunk
        finally:
            self._restore_datetime(obj, replaced)


# =============================================================================
# ----- PBKDF2 ----------------------------------------------------------------
# =============================================================================

#: Default number of iterations.
#:
#: Note that while the :func:`pbkdf2` function copied from another
#: library has its own default values. However, when used by
#: :mod:`safe`,  the defaults are defined by this value and
#: :data:`PBKDF2_DEFAULT_SALT_LENGTH`.
#:
#: :type: :class:`int`
PBKDF2_DEFAULT_ITERATIONS = 32768

#: Default salt length.
#:
#: See note on :data:`PBKDF2_DEFAULT_ITERATIONS`.
#:
#: :type: :class:`int`
PBKDF2_DEFAULT_SALT_LENGTH = 32

#: Struct pack method used by :func:`pbkdf2`.
#:
#: :type: :meth:`struct.Struct.pack`
pbkdf2_pack_int = struct.Struct('>I').pack


def pbkdf2(data, salt, iterations=1000, keylen=24, codec='base64_codec'):
    """
    Return PBKDF2/SHA-1 digest for ``data``.

    From https://github.com/mitsuhiko/python-pbkdf2/.

    :param str data: Password from which to derive a key.
    :param str salt: Salt.
    :param int iterations: Number of pbkdf2 iterations to do. Defaults to
                           ``1000``.
    :param int keylen: Desired key length, in bytes. Defaults to ``24``.
    :param str codec: Codec to use to encode return value. Defaults to
                      ``'base64_codec'``.
    :return: PBKDF2/SHA1 digest encoded with ``codec``.
    :rtype: str
    :copyright: (c) Copyright 2011 by Armin Ronacher.
    :license: BSD
    """
    mac = hmac.new(data, None, hashlib.sha1)

    def _pseudorandom(x, mac=mac):
        hmac = mac.copy()
        hmac.update(x)
        return map(ord, hmac.digest())

    buf = []
    for block in xrange(1, -(-keylen // mac.digest_size) + 1):
        rv = u = _pseudorandom(salt + pbkdf2_pack_int(block))
        for i in xrange(iterations - 1):
            u = _pseudorandom(''.join(map(chr, u)))
            rv = itertools.starmap(operator.xor, itertools.izip(rv, u))
        buf.extend(rv)
    return ''.join(map(chr, buf))[:keylen].encode(codec).strip()


# =============================================================================
# ----- Utilities -------------------------------------------------------------
# =============================================================================

def expand_path(path):
    """
    Return absolute path, with variables and ``~`` expanded.

    :param str path: Path, possibly with variables and ``~``.
    :return: Absolute path with special sequences expanded.
    :rtype: str
    """
    return os.path.abspath(os.path.expanduser(os.path.expandvars(path)))


def generate_key(password, size, backend=None):
    """
    Generate a key via PBKDF2 and returns key and parameters.

    Returns a 3-tuple containing ``(key, iterations, salt)``.

    :param str password: Password from which to derive the key.
    :param int size: Desired length of the key, in bytes.
    :param str backend: Name of the backend for which to generate the key. If
                        ``--<backend>-pbkdf2-iterations`` and/or
                        ``--<backend>-pbkdf2-salt-length`` was specified, those
                        values will be used. Otherwise
                        :data:`PBKDF2_DEFAULT_ITERATIONS` and
                        :data:`PBKDF2_DEFAULT_SALT_LENGTH` will be used.
    :return: 3-tuple: ``(key, iterations, salt)``.
    :rtype: tuple
    """
    arg = '%s_pbkdf2_iterations' % backend
    iterations = getattr(args, arg, PBKDF2_DEFAULT_ITERATIONS)
    arg = '%s_pbkdf2_salt_length' % backend
    salt_length = getattr(args, arg, PBKDF2_DEFAULT_SALT_LENGTH)
    salt = binascii.hexlify(random_bytes(salt_length))
    return pbkdf2(password, salt, iterations, size), iterations, salt


def get_executable(name):
    """
    Return the full path to executable named ``name``, if it exists.

    :param str name: Name of the executable to find.
    :return: Full path to the executable or ``None``.
    :rtype: :class:`str` or :data:`None`
    """
    directories = filter(None, os.environ.get('PATH', '').split(os.pathsep))
    for directory in directories:
        path = os.path.join(directory.strip('"'), name)
        if os.path.isfile(path) and os.access(path, os.X_OK):
            return path


def prompt_boolean(prompt, default=False):
    """
    Prompt the user for a yes or no answer.

    :param str prompt: Prompt to display to the user. Will have " [Y/n]" or
                       " [y/N]" appended, depending on the value of
                       ``default``.
    :param bool default: Default value. Defaults to :data:`False`.
    :return: User's answer.
    :rtype: bool
    """
    postfix = ' [Y/n] ' if default else ' [y/N] '
    while True:
        yn = raw_input(prompt + postfix).lower()
        if not yn:
            return default
        if yn[0] not in ('n', 'y'):
            continue
        return True if yn[0] == 'y' else False


def prompt_for_new_password():
    """
    Prompt user for a new password (with confirmation) and return it.

    :return: Confirmed user-generated password.
    :rtype: str
    """
    while True:
        password = getpass.getpass('New password: ')
        confirm = getpass.getpass('Confirm new password: ')
        if password == confirm:
            return password
        print >> sys.stderr, 'error: passwords did not match'


def prompt_until_decrypted(fn, password=None):
    """
    Prompt a user for a password until data is successfully decrypted.

    This function Assumes that ``fn`` raises a :exc:`SafeCryptographyError` if
    decryption is unsucessful. Returns 2-tuple of
    ``(password, decrypted data)``.

    :param fn: Function to call to decrypt data. Should take a single argument:
               the password to be used for decryption. If decryption fails, the
               function should raise an exception that is a subclass of
               :exc:`SafeCryptographyError`.
    :type fn: ``fn(string) -> (password<str>, decrypted_data<str>)``
    :param password: Initial password to try. If this fails, no error message
                     will be printed to the console. If ``None``, user is
                     immediately prompted for a password.
    :type password: :class:`str` or ``None``
    :return: 2-tuple: ``(password, decrypted data)``.
    :rtype: tuple
    """
    while True:
        prompt_for_password = password is None
        if prompt_for_password:
            password = getpass.getpass('Password: ')
        try:
            return password, load_json(fn(password))
        except SafeError:
            if prompt_for_password:
                print >> sys.stderr, 'error: failed to decrypt safe'
            password = None


def prompt_until_decrypted_pbkdf2(fn, data, key_size, password=None):
    """
    Wrapper for :func:`prompt_until_decrypted` for backends that use PBKDF2.

    :param fn: Function to call to decrypt data. Should take two arguments:
               a string containing the data to be decrypted and a string
               containing the key, generated from PBKDF2. If decryption
               fails, the function should raise an exception that is a
               subclass of :exc:`SafeCryptographyError`.
    :type fn: ``fn(string, string) -> (password, decrypted dta)``
    :param dict data: Dictionary containing ``data``, ``iterations``, and
                      ``salt`` keys. These should be populated with the
                      encrypted data, the number of PBKDF2 iterations used to
                      encrypt the data, and the PBKDF2 salt used to encrypt
                      the data, respectively.
    :param int key_size: Size of the key used to encrypt the data, in bytes.
    :param password: See :func:`prompt_until_decrypted`.
    :return: 2-tuple: ``(password, decrypted data)``.
    :rtype: tuple
    """
    def wrapper(password):
        key = pbkdf2(password, data['salt'], data['iterations'], key_size)
        return fn(data['data'], key)
    return prompt_until_decrypted(wrapper, password)


# =============================================================================
# ----- Backend: Base ---------------------------------------------------------
# =============================================================================

#: Dictionary mapping backend names (strings) to classes.
#:
#: :type: :class:`dict`
backend_map = dict()


class BackendNameConflictError(SafeError):
    """
    Raised when a backend name conflicts with an existing backend name.

    :param str name: Name of the backend in conflict.
    """

    def __init__(self, name):
        msg = 'Backend named "%s" already exists' % name
        super(BackendNameConflictError, self).__init__(msg)


def backend(name):
    '''
    Class decorator for registering backends.

    Raises :exc:`BackendNameConflictError` if ``name`` has already been
    registered.

    Example::

        @backend('example')
        class ExampleSafeBackend(SafeBackend):
            """Example safe backend."""
            ...

    :param str name: Human-friendly name to use for the backend.
    :raises BackendNameConflictError: if ``name`` has already been registered.
    :returns: Class decorated with ``@backend`` (unchanged).
    :rtype: type
    '''
    if name in backend_map:
        raise BackendNameConflictError(name)

    def decorator(cls):
        """
        Register the class with :data:`backend_map` and return the class.

        :param cls: Backend class.
        :type cls: type
        :return: Class that was passed in, unchanged.
        :rtype: type
        """
        backend_map[name] = cls
        return cls

    return decorator


def get_supported_backend_names():
    """
    Return sorted list of available backend names.

    Available backends are determined by the cryptography tools available on
    the current system.

    :return: Sorted list of backend names.
    :rtype: list
    """
    rv = []
    for name, cls in backend_map.iteritems():
        if cls.supports_platform():
            rv.append(name)
    return sorted(rv)


class SafeBackend(object):
    """
    Base class for safe backends.

    Subclasses must override :meth:`supports_platform`, :meth:`read`,
    :meth:`write`, and should override :meth:`add_arguments` if they have
    arguments to add to the command-line. See the documentation for those
    methods for more information.

    :param str password: Password for the safe.
    """

    @staticmethod
    def add_arguments():
        """
        Add arguments to the top-level command.

        Subclasses may override this method.

        If a subclass wishes to add command-line arguments, it should
        override this method and use the global ``parser`` object to add the
        arguments. Note:

        * Required arguments *must* be avoided; the user may not actually be
          using this backend.
        * Short arguments *should* be avoided in order to steer clear of
          conflicting option names.
        * Argument names should be prefixed with the class' name as registered
          with the :func:`backend` decorator.

        Example::

            @backend('example')
            class ExampleSafeBackend(SafeBackend):
                @staticmethod
                def add_argument():
                    parser.add_argument(
                        '--example-option',
                        help="this sets `option' for the example backend",
                    )

        :rtype: None
        """

    @staticmethod
    def supports_platform():
        """
        Indicate support for the current platform.

        Suclasses must override this method.

        :raises NotImplementedError: if not overridden
        :return: Boolean indicating whether this backend is supported on this
                 platform.
        :rtype: bool
        """
        raise NotImplementedError

    def __init__(self, password=None):
        #: Password used for encrypting and decrypting the safe.
        #:
        #: :type: :class:`str`
        self.password = password

    def __repr__(self):
        """Return human-friendly representation for the backend."""
        rv = u'<%s>' % self.__class__.__name__
        for name, cls in backend_map.iteritems():
            if cls is self.__class__:
                rv = u'<%s (%s)>' % (self.__class__.__name__, name)
                break
        return rv

    def read(self, path):
        """
        Return decrypted data from file at ``path``.

        Subclasses must override this method.

        :raises NotImplementedError: if not overridden
        :param str path: Path to the file containing encrypted data.
        :return: Decrypted and decoded JSON object.
        :rtype: object
        """
        raise NotImplementedError

    def write(self, path, data):
        """
        Write ``data`` to encrypted file at ``path``.

        Subclasses must override this method.

        :raises NotImplementedError: if not overridden
        :param str path: Path to file where encrypted data should be written.
        :param data: Data to write to ``path``.
        :type data: JSON-encodable data (including :class:`datetime.datetime`)
        :rtype: None
        """
        raise NotImplementedError


# =============================================================================
# ----- Backend: Bcrypt -------------------------------------------------------
# =============================================================================

#: Default number of times to overwrite plaintext files after encryption.
#:
#: :type: :class:`int`
BCRYPT_DEFAULT_OVERWRITES = 7


class BcryptError(SafeError):
    """Base class for errors in the bcrypt backend."""


class BcryptCryptographyError(BcryptError, SafeCryptographyError):
    """Raised when there are errors encrypting or decrypting data."""


class BcryptFilenameError(BcryptError):
    """Raised when trying to encrypt or decrypt an invalid filename."""


@backend('bcrypt')
class BcryptSafeBackend(SafeBackend):
    """Backend that uses the bcrypt command-line tool."""

    #: Full path to the bcrypt executable, calculated by
    #: :func:`get_executable`.
    #:
    #: :type: :class:`str`
    bcrypt = get_executable('bcrypt')

    @staticmethod
    def add_arguments():
        """
        Override method to add command-line arguments for this backend.

        Adds ``--bcrypt-overwrites`` option to allow the user to specify the
        number of times an original plaintext file is overwritten once it
        has been encrypted.

        .. seealso::

            Superclass documentation: :meth:`SafeBackend.add_arguments`
        """
        parser.add_argument(
            '--bcrypt-overwrites',
            default=BCRYPT_DEFAULT_OVERWRITES,
            help='number of times to overwrite plaintext in file (default: '
                 '%(default)s)',
            metavar='NUMBER',
            type=int,
        )

    @classmethod
    def supports_platform(cls):
        """
        Override method to indicate platform support.

        Platform is supported if :attr:`bcrypt` command was found.

        .. seealso::

           Superclass documentation: :meth:`SafeBackend.supports_platform`.
        """
        return cls.bcrypt

    def decrypt(self, path, password):
        """
        Decrypt file at ``path`` using ``password``.

        This method immediately re-encrypts the file after decryption.

        :param str path: Path to the file to decrypt. **Must end in** ``.bfe``.
        :param str password: Password to decrypt file.
        :raises BcryptFilenameError: if filename does not end with ``.bfe``.
        :raises BcryptCryptographyError: if the bcrypt command has a nonzero
                                         exit.
        :return: Decrypted file contents.
        :rtype: str
        """
        if not path.endswith('.bfe'):
            raise BcryptFilenameError('filename must end with .bfe')
        process = pexpect.spawn('%s %s' % (self.bcrypt, path))
        process.expect('Encryption key:', timeout=5)
        process.sendline(password)
        out = process.read()
        process.close()
        if process.exitstatus:
            raise BcryptCryptographyError('failed to decrypt: %s' % out)
        else:
            try:
                with open(path[:-4]) as f:
                    return f.read()
            finally:
                self.encrypt(path[:-4], password)

    def encrypt(self, path, password):
        """
        Encrypt file at ``path`` with ``password``.

        The encrypted filename is the original filename plus ``.bfe``.

        :param str path: Path to the file to decrypt. **Must not end in**
                         ``.bfe``.
        :param str password: Password with which to encrypt file.
        :raises BcryptFilenameError: if filename ends with ``.bfe``.
        :raises BcryptCryptographyError: if the bcrypt command has a nonzero
                                         exit.
        :rtype: None
        """
        if path.endswith('.bfe'):
            raise BcryptFilenameError('path cannot end with .bfe')
        command = '%s -s%i %s' % (self.bcrypt, args.bcrypt_overwrites, path)
        process = pexpect.spawn(command)
        process.expect('Encryption key:', timeout=5)
        process.sendline(password)
        process.expect('Again:', timeout=5)
        process.sendline(password)
        out = process.read()
        process.close()
        if process.exitstatus:
            raise BcryptCryptographyError('failed to encrypt: %s' % out)

    def read(self, path):
        """
        Override method to implement reading with this backend.

        Reading is done using a combination of :func:`prompt_until_decrypted`
        and :meth:`decrypt`.

        .. seealso:: Superclass documentation: :meth:`SafeBackend.read`.
        """
        tmp_directory = tempfile.mkdtemp()
        try:
            tmp = os.path.join(tmp_directory, 'safe.bfe')
            shutil.copy(path, tmp)
            self.password, rv = prompt_until_decrypted(
                functools.partial(self.decrypt, tmp),
                self.password,
            )
            return rv
        finally:
            shutil.rmtree(tmp_directory)

    def write(self, path, data):
        """
        Override method to implement writing with this backend.

        Note that bcrypt passwords must be 8 to 56 characters long, inclusive.
        If :attr:`SafeBackend.password` is not set, or is set but is not within
        those bounds, this will use :func:`prompt_for_new_password` until a
        new, valid password is supplied. The actual encryption is done using
        :meth:`encrypt`.

        .. seealso:: Superclass documentation: :meth:`SafeBackend.write`.
        .. seealso:: See :meth:`encrypt` for exceptions this method may throw.
        """
        if self.password is None:
            self.password = prompt_for_new_password()
            msg = 'error: bcrypt passphrases must be 8 to 56 characters'
            while not 7 < len(self.password) < 57:
                print >> sys.stderr, msg
                self.password = prompt_for_new_password()
        fd, fp = tempfile.mkstemp()
        try:
            f = os.fdopen(fd, 'w')
            dump_json(data, f)
            f.close()
        except:
            try:
                os.close(fd)
            except OSError:
                pass
            os.unlink(fp)
            raise
        try:
            self.encrypt(fp, self.password)
        except:
            os.unlink(fp)
            raise
        os.rename(fp + '.bfe', path)


# =============================================================================
# ----- Backend: Fernet -------------------------------------------------------
# =============================================================================

class FernetCryptographyError(SafeCryptographyError):
    """Raised when the cryptography backend fails to decrypt input."""


@backend('fernet')
class FernetSafeBackend(SafeBackend):
    """Backend that uses :class:`cryptography.fernet.Fernet`."""

    #: Key size for the Ferney encryption algorithm.
    #:
    #: :type: :class:`int`
    KEY_SIZE = 32

    @staticmethod
    def add_arguments():
        """
        Override method to add command-line arguments for this backend.

        Adds ``--fernet-pbkdf2-iterations`` and ``--fernet-pbkdf2-salt-length``
        arguments to allow the user to control the PBKDF2 parameters used when
        generating the key.

        .. seealso::

            Superclass documentation: :meth:`SafeBackend.add_arguments`
        """
        parser.add_argument(
            '--fernet-pbkdf2-iterations',
            default=PBKDF2_DEFAULT_ITERATIONS,
            help='number of iterations for PBKDF2 (default: %(default)s)',
            metavar='NUMBER',
            type=int,
        )
        parser.add_argument(
            '--fernet-pbkdf2-salt-length',
            default=PBKDF2_DEFAULT_SALT_LENGTH,
            help='salt length for PBKDF2 (bytes) (default: %(default)s)',
            metavar='NUMBER',
            type=int,
        )

    @staticmethod
    def supports_platform():
        """
        Override method to indicate platform support.

        Platform is supported if :data:`CRYPTOGRAPHY_INSTALLED` is
        :data:`True`.

        .. seealso::

           Superclass documentation: :meth:`SafeBackend.supports_platform`.
        """
        return CRYPTOGRAPHY_INSTALLED

    def decrypt(self, data, key):
        """
        Decrypt ``data`` using ``key``.

        :param str data: Data to decrypt.
        :param str key: Key with which to decrypt ``data``.
        :raises FernetCryptographyError: if data cannot be decrypted.
        :returns: Decrypted data.
        :rtype: str
        """
        try:
            return CryptographyFernet(key).decrypt(bytes(data))
        except CryptographyInvalidToken, e:
            raise FernetCryptographyError(e.message)

    def read(self, path):
        """
        Override method to implement reading with this backend.

        Reading is done using a combination of
        :func:`prompt_until_decrypted_pbkdf2` and :meth:`decrypt`.

        .. seealso:: Superclass documentation: :meth:`SafeBackend.read`.
        """
        with open(path) as f:
            data = load_json(f)
        self.password, rv = prompt_until_decrypted_pbkdf2(
            self.decrypt,
            data,
            self.KEY_SIZE,
            self.password,
        )
        return rv

    def write(self, path, data):
        """
        Override method to implement writing with this backend.

        If :attr:`SafeBackend.password` is not set, this uses
        :func:`prompt_for_new_password` to get the password to use.

        .. seealso:: Superclass documentation: :meth:`SafeBackend.write`.
        """
        if self.password is None:
            self.password = prompt_for_new_password()
        key, iterations, salt = generate_key(
            self.password,
            self.KEY_SIZE,
            'fernet',
        )
        box = CryptographyFernet(bytes(key))
        dump_json(dict(
            data=box.encrypt(bytes(dump_json(data))),
            iterations=iterations,
            salt=salt,
        ), path)


# =============================================================================
# ----- Backend: GPG ----------------------------------------------------------
# =============================================================================

#: Default GPG cipher to use.
#:
#: :type: :class:`str`
GPG_DEFAULT_CIPHER = 'cast5'


class GPGCryptographyError(SafeCryptographyError):
    """Raised when the gpg backend fails to encrypt or decrypt data."""


@backend('gpg')
class GPGSafeBackend(SafeBackend):
    """Backend that uses GPG2's command line tools' symmetric ciphers."""

    #: Full path to the gpg executable, calculated by :func:`get_executable`.
    #:
    #: :type: :class:`str`
    gpg = get_executable('gpg2')

    @classmethod
    def add_arguments(cls):
        """
        Override method to add command-line arguments for this backend.

        Adds two options:

        * ``--gpg-ascii`` -- Allows the user to control whether the backend
          encrypts to an ascii-based file format. (By default it encrypts to
          a binary format.)
        * ``--gpg-cipher`` -- Allows the user to control the cipher algorithm
          gpg uses to encrypt the data. Defaults to :data:`GPG_DEFAULT_CIPHER`.

        The cipher list is calculated dynamically by running ``gpg --version``
        and parsing the list of available ciphers.

        .. seealso::

            Superclass documentation: :meth:`SafeBackend.add_arguments`
        """
        process = pexpect.spawn('%s --version' % cls.gpg)
        out = process.read()
        process.close()
        match = re.search(r'Cipher:\s+(.+)Hash:', out, re.DOTALL)
        matches = match.group(1).split()
        ciphers = sorted(cipher.strip(',').lower() for cipher in matches)
        parser.add_argument(
            '--gpg-ascii',
            action='store_true',
            default=False,
            help='use GPG ASCII format rather than binary',
        )
        parser.add_argument(
            '--gpg-cipher',
            choices=ciphers,
            default=GPG_DEFAULT_CIPHER,
            help='gpg cipher to use (choices: %(choices)s) (default: '
                 '%(default)s)',
            metavar='GPG_CIPHER',
        )

    @classmethod
    def supports_platform(cls):
        """
        Override method to indicate platform support.

        Platform is supported if :attr:`gpg` is found.

        .. seealso::

           Superclass documentation: :meth:`SafeBackend.supports_platform`.
        """
        return cls.gpg

    def decrypt(self, path, password):
        """
        Decrypt file at ``path`` using ``password``.

        :param str path: Path to the file to decrypt.
        :param str password: Password to decrypt file.
        :raises GPGCryptographyError: if the gpg command has a nonzero exit.
        :return: Decrypted file contents.
        :rtype: str
        """
        command = ' '.join((
            self.gpg,
            '--batch',
            '--decrypt',
            '--passphrase',
            password,
            path,
        ))
        process = pexpect.spawn(command)
        out = process.read()
        process.close()
        if process.exitstatus:
            raise GPGCryptographyError('failed to decrypt safe: %s' % out)
        lines = []
        for line in out.splitlines():
            if not line.startswith('gpg:'):
                lines.append(line)
        return '\n'.join(lines)

    def read(self, path):
        """
        Override method to implement reading with this backend.

        Reading is done using a combination of :func:`prompt_until_decrypted`
        and :meth:`decrypt`.

        .. seealso:: Superclass documentation: :meth:`SafeBackend.read`.
        """
        tmp_directory = tempfile.mkdtemp()
        try:
            tmp = os.path.join(tmp_directory, 'safe.gpg')
            shutil.copy(path, tmp)
            self.password, rv = prompt_until_decrypted(
                functools.partial(self.decrypt, tmp),
                self.password,
            )
        finally:
            shutil.rmtree(tmp_directory)
        return rv

    def write(self, path, data):
        """
        Override method to implement writing with this backend.

        If :attr:`SafeBackend.password` is not set, this uses
        :func:`prompt_for_new_password` to get the password to use.

        :raises GPGCryptographyError: if encryption fails

        .. seealso:: Superclass documentation: :meth:`SafeBackend.write`.
        """
        if self.password is None:
            self.password = prompt_for_new_password()
        tmp_directory = tempfile.mkdtemp()
        try:
            tmp = os.path.join(tmp_directory, 'safe.gpg')
            command = ' '.join((
                self.gpg,
                '--armor' if args.gpg_ascii else '',
                '--batch',
                '--cipher-algo',
                args.gpg_cipher.upper(),
                '--output',
                tmp,
                '--passphrase',
                self.password.replace('"', r'\"'),
                '--symmetric',
            ))
            process = pexpect.spawn(command)
            process.sendline(dump_json(data))
            process.sendeof()
            out = process.read()
            process.close()
            if process.exitstatus:
                msg = 'failed to gpg encrypt file: %s' % out
                raise GPGCryptographyError(msg)
            os.rename(tmp, path)
        finally:
            shutil.rmtree(tmp_directory)


# =============================================================================
# ----- Backend: NaCl ---------------------------------------------------------
# =============================================================================

class NaClCryptographyError(SafeCryptographyError):
    """Raised when the nacl backend fails to decrypt input."""


@backend('nacl')
class NaClSafeBackend(SafeBackend):
    """Backend that uses :class:`nacl.secret.SecretBox`."""

    #: Nonce used for encryption and decryption. Because we
    #: generate a new random salt (and thus a new key) each time
    #: the data is encrypted, it's cryptographically fine to use
    #: a static nonce.
    #:
    #: :type: :class:`str`
    NONCE = '0' * 24

    @staticmethod
    def add_arguments():
        """
        Override method to add command-line arguments for this backend.

        Adds ``--nacl-pbkdf2-iterations`` and ``--nacl-pbkdf2-salt-length``
        arguments to allow the user to control the PBKDF2 parameters used when
        generating the key.

        .. seealso::

            Superclass documentation: :meth:`SafeBackend.add_arguments`
        """
        parser.add_argument(
            '--nacl-pbkdf2-iterations',
            default=PBKDF2_DEFAULT_ITERATIONS,
            help='number of iterations for PBKDF2 (default: %(default)s)',
            metavar='NUMBER',
            type=int,
        )
        parser.add_argument(
            '--nacl-pbkdf2-salt-length',
            default=PBKDF2_DEFAULT_SALT_LENGTH,
            help='salt length for PBKDF2 (bytes) (default: %(default)s)',
            metavar='NUMBER',
            type=int,
        )

    @staticmethod
    def supports_platform():
        """
        Override method to indicate platform support.

        Platform is supported if :data:`NACL_INSTALLED` is :data:`True`.

        .. seealso::

           Superclass documentation: :meth:`SafeBackend.supports_platform`.
        """
        return NACL_INSTALLED

    def decrypt(self, data, key, nonce):
        """
        Decrypt ``data`` using ``key`` and ``nonce``.

        :param str data: Base64-encoded encrypted data.
        :param str key: Base64-encoded key.
        :param str nonce: Nonce used to encrypt the data.
        :raises NaClCryptographyError: if data cannot be decrypted.
        :returns: Decrypted data.
        :rtype: str
        """
        data, nonce = bytes(data), bytes(nonce)
        box = NaClSecretBox(bytes(key), NaClBase64Encoder)
        try:
            return box.decrypt(data, nonce, NaClBase64Encoder)
        except NaClCryptoError, e:
            raise NaClCryptographyError(e.message)

    def encrypt(self, data, key, nonce):
        """
        Encrypt ``data`` using ``key`` and ``nonce``.

        :param str data: Data to be encrypted.
        :param str key: Base64-encoded key.
        :param str nonce: Nonce to use to encrypt data.
        :returns: Encrypted data.
        :rtype: str
        """
        box = NaClSecretBox(bytes(key), NaClBase64Encoder)
        message = box.encrypt(bytes(data), bytes(nonce), NaClBase64Encoder)
        return message.ciphertext

    def read(self, path):
        """
        Override method to implement reading with this backend.

        Reading is done using a combination of
        :func:`prompt_until_decrypted_pbkdf2` and and :meth:`decrypt`.

        .. seealso:: Superclass documentation: :meth:`SafeBackend.read`.
        """
        with open(path) as f:
            data = load_json(f)
        self.password, rv = prompt_until_decrypted_pbkdf2(
            functools.partial(self.decrypt, nonce=self.NONCE),
            data,
            NaClSecretBox.KEY_SIZE,
            self.password,
        )
        return rv

    def write(self, path, data):
        """
        Override method to implement writing with this backend.

        If :attr:`SafeBackend.password` is not set, this uses
        :func:`prompt_for_new_password` to get the password to use.

        This method then derives a key of size
        :attr:`nacl.secret.SecretBox.KEY_SIZE` using :func:`generate_key` with
        salt length and iteration count controlled by the parameters from
        :meth:`add_arguments`. It then encrypts the data using the derived key
        and :attr:`NONCE`.

        .. seealso:: Superclass documentation: :meth:`SafeBackend.write`.
        """
        if self.password is None:
            self.password = prompt_for_new_password()
        key, iterations, salt = generate_key(
            self.password,
            NaClSecretBox.KEY_SIZE,
            'nacl',
        )
        dump_json(dict(
            data=self.encrypt(dump_json(data), key, self.NONCE),
            iterations=iterations,
            salt=salt,
        ), path)


# =============================================================================
# ----- Backend: Plaintext ----------------------------------------------------
# =============================================================================

@backend('plaintext')
class PlaintextSafeBackend(SafeBackend):
    """Not an actual safe. Reads and writes cleartext JSON."""

    @staticmethod
    def supports_platform():
        """
        Override method to indicate platform support.

        The plaintext backend is supported on all platforms.

        .. seealso::

           Superclass documentation: :meth:`SafeBackend.supports_platform`.
        """
        return True

    def read(self, path):
        """
        Override method to implement reading with this backend.

        Reading is done using :func:`load_json`.

        .. seealso:: Superclass documentation: :meth:`SafeBackend.read`.
        """
        with open(path) as f:
            return load_json(f)

    def write(self, path, data):
        """
        Override method to implement writing with this backend.

        Writing is done using :func:`dump_json`.

        .. seealso:: Superclass documentation: :meth:`SafeBackend.write`.
        """
        with open(path, 'w') as f:
            dump_json(data, f)


# =============================================================================
# ----- Database --------------------------------------------------------------
# =============================================================================

class Database(object):
    IGNORED_MODELS = ('_sa_module_registry',)

    def __init__(self):
        self._models = dict()

        class QueryProperty(object):
            def __init__(self, db):
                self.db = db

            def __get__(self, _, type):
                mapper = sqlalchemy.orm.class_mapper(type)
                return sqlalchemy.orm.Query(mapper, session=self.db.session)

        declarative_base = sqlalchemy.ext.declarative.declarative_base
        self.Model = declarative_base(class_registry=self._models)
        self.Model.query = QueryProperty(self)

        for module in (sqlalchemy, sqlalchemy.orm):
            for attr in module.__all__:
                if not hasattr(self, attr):
                    setattr(self, attr, getattr(module, attr))

        for attr in dir(sqlalchemy_utils):
            if attr.endswith('Type'):
                name = attr[:-4]
                if not hasattr(self, name):
                    setattr(self, name, getattr(sqlalchemy_utils, attr))

        self.initialize()

    def initialize(self):
        self.engine = sqlalchemy.create_engine('sqlite://')
        self.session = sqlalchemy.orm.sessionmaker(bind=self.engine)()
        metadata = self.Model.metadata
        metadata.create_all(bind=self.engine, tables=metadata.tables.values())

    @property
    def models(self):
        return dict([
            (name, cls) for name, cls in self._models.iteritems()
            if name not in self.IGNORED_MODELS
        ])

    def dump(self):
        rv = dict()
        for name, cls in self.models.iteritems():
            rv[name] = [obj.dump() for obj in cls.query.all()]
        return rv

    def load(self, data):
        self.initialize()

        secrets = dict()
        for d in data.get('Secret', []):
            id = d.pop('id')
            secret = Secret(**d)
            self.session.add(secret)
            secrets[id] = secret
        self.session.commit()

        for name, cls in self.models.iteritems():
            if name != 'Secret':
                for d in data.get(name, []):
                    del d['id']
                    d['secret_id'] = secrets[d['secret_id']].id
                    self.session.add(cls(**d))
        self.session.commit()


db = Database()


# ----- Models ----------------------------------------------------------------

#: Default length in characters for new secrets.
#:
#: :type: :class:`int`
DEFAULT_NEW_SECRET_LENGTH = 128


class Sensitivity(object):
    HIGH = u'high'
    MODERATE = u'moderate'
    LOW = u'low'
    DEFAULT = HIGH


class ModelMixin(object):
    id = db.Column(db.Integer, primary_key=True)
    created = db.Column(db.Arrow, default=arrow.utcnow, nullable=False)

    def dump(self):
        rv = dict()
        for key in self.__table__.columns.keys():
            method_name = 'dump_%s' % key
            method_default = functools.partial(getattr, self, key)
            rv[key] = getattr(self, method_name, method_default)()
        return rv

    def dump_created(self):
        return self.created.datetime


class Secret(db.Model, ModelMixin):
    __tablename__ = 'secret'
    active = db.Column(db.Boolean, default=True, nullable=False)
    autoupdate = db.Column(db.Boolean, default=True, nullable=False)
    description = db.Column(db.Text)
    email_query = db.relationship('Email', lazy='dynamic')
    emails = db.relationship('Email')
    exclude = db.Column(db.String(255), default='', nullable=False)
    length = db.Column(
        db.Integer,
        default=DEFAULT_NEW_SECRET_LENGTH,
        nullable=False,
    )
    sensitivity = db.Column(
        db.Choice((
            (Sensitivity.HIGH, u'High'),
            (Sensitivity.MODERATE, u'Moderate'),
            (Sensitivity.LOW, u'Low'),
        )),
        default=Sensitivity.DEFAULT,
        nullable=False,
    )
    site_query = db.relationship('Site', lazy='dynamic')
    sites = db.relationship('Site')
    slug_query = db.relationship('Slug', lazy='dynamic')
    slugs = db.relationship('Slug')
    username_query = db.relationship('Username', lazy='dynamic')
    usernames = db.relationship('Username')
    value_query = db.relationship('Value', lazy='dynamic')
    values = db.relationship('Value')


class SecretMixin(ModelMixin):
    # N805: first argument of a method should be named self
    # It's not clear whether this is an instance or class method. In
    # any case, it doesn't matter because we don't use it. So the
    # variable name is _ to underscore that fact.

    @sqlalchemy.ext.declarative.declared_attr
    def secret(_):  # noqa: N805
        return db.relationship('Secret')

    @sqlalchemy.ext.declarative.declared_attr
    def secret_id(_):  # noqa: N805
        return db.Column(
            db.Integer,
            db.ForeignKey('secret.id'),
            nullable=False,
        )


class Email(db.Model, SecretMixin):
    __tablename__ = 'email'
    email = db.Column(db.String(255), nullable=False)


class Site(db.Model, SecretMixin):
    __tablename__ = 'site'
    site = db.Column(db.String(255), nullable=False)


class Slug(db.Model, SecretMixin):
    __tablename__ = 'slug'
    slug = db.Column(db.String(255), nullable=False)


class Username(db.Model, SecretMixin):
    __tablename__ = 'username'
    username = db.Column(db.String(255), nullable=False)


class Value(db.Model, SecretMixin):
    __tablename__ = 'value'
    value = db.Column(db.Text, nullable=False)


# =============================================================================
# ----- Application -----------------------------------------------------------
# =============================================================================

#: Envvar containing the backend.
#:
#: :type: :class:`str`
BACKEND_ENVVAR = 'SAFE_BACKEND'

#: Operation canceled by user.
#:
#: :type: :class:`int`
ERR_CANCELED = 10

#: Envvar containing the path to the safe.
#:
#: :type: :class:`str`
PATH_ENVVAR = 'SAFE_PATH'

#: Preferred backends, in priority order.
#:
#: :type: :func:`tuple`
PREFERRED_BACKENDS = ('gpg', 'bcrypt', 'nacl', 'fernet', 'plaintext')


@app
def safe():
    """Command-line application for storing and managing secrets."""
    backend_names = get_supported_backend_names()
    default_backend_name = None
    if BACKEND_ENVVAR in os.environ:
        backend_name = os.environ[BACKEND_ENVVAR]
        if backend_name in backend_names:
            default_backend_name = backend_name
        else:
            fmt = 'warning: %s specifies an unknown backend: %s'
            print >> sys.stderr, fmt % (BACKEND_ENVVAR, backend_name)
    if default_backend_name is None:
        for name in PREFERRED_BACKENDS:  # pragma: no branch
            if name in backend_names:
                default_backend_name = name
                break
    parser.add_argument(
        '-b',
        '--backend',
        choices=backend_names,
        default=default_backend_name,
        help='crypto backend (choices: %(choices)s) (default: %(default)s)',
        metavar='BACKEND',
    )

    kwargs = dict(default=None, help='file to read from', required=True)
    if PATH_ENVVAR in os.environ:
        kwargs.update(dict(
            default=os.environ[PATH_ENVVAR],
            help='file to read from (default from %s: %%(default)s)' %
                 PATH_ENVVAR,
            required=False,
        ))
    parser.add_argument('-f', '--file', **kwargs)

    for name in backend_names:
        backend_map[name].add_arguments()

    yield

    g.path = expand_path(args.file)
    g.safe = backend_map[args.backend]()
    safe_exists = os.path.exists(g.path)
    try:
        if safe_exists:
            db.load(g.safe.read(g.path))
        if subcommand() and (Secret.query.count() > 0 or safe_exists):
            g.safe.write(g.path, db.dump())
    except KeyboardInterrupt:
        print
        yield ERR_CANCELED


if __name__ == '__main__':  # pragma: no cover
    safe.main()
