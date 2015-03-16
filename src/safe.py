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
import subprocess
import sys
import tempfile
import time
import warnings

from clik import app, args, g, parser, subcommand
from clik.util import AttributeDict
import pexpect

from os import urandom as random

try:
    from cryptography.fernet import Fernet as CryptographyFernet, \
        InvalidToken as CryptographyInvalidToken
    cryptography_installed = True
except ImportError:  # pragma: no cover
    cryptography_installed = False

try:
    with warnings.catch_warnings():
        warnings.simplefilter('ignore')
        from nacl.encoding import Base64Encoder as NaClBase64Encoder
        from nacl.exceptions import CryptoError as NaClCryptoError
        from nacl.secret import SecretBox as NaClSecretBox
        from nacl.utils import random  # noqa
    nacl_installed = True
except ImportError:  # pragma: no cover
    nacl_installed = False


__version__ = '0.2'


# =============================================================================
# ----- Exceptions ------------------------------------------------------------
# =============================================================================

class SafeError(Exception):
    """Base class for all exceptions raised from this module."""


class SafeCryptographyError(SafeError):
    """Base class for crypto-related errors."""


class BcryptError(SafeError):
    """Base class for errors in the bcrypt backend."""


class BcryptCryptographyError(BcryptError, SafeCryptographyError):
    """Raised when there are errors encrypting or decrypting data."""


class BcryptFilenameError(BcryptError):
    """Raised when trying to encrypt or decrypt an invalid filename."""


class CryptographyError(SafeCryptographyError):
    """Raised when the cryptography backend fails to decrypt input."""


class GPGError(SafeCryptographyError):
    """Raised on errors in the gpg backend."""


class NaClError(SafeCryptographyError):
    """Raised when the nacl backend fails to decrypt input."""


class NameConflictError(SafeError):
    """
    Raised when a backend name conflicts with an existing backend name.

    :param str name: Name of the backend in conflict.
    """
    def __init__(self, name):
        msg = 'Backend named "%s" already exists' % name
        super(NameConflictError, self).__init__(msg)


# =============================================================================
# ----- JSON+Datetime ---------------------------------------------------------
# =============================================================================

date_re = re.compile(r'\\/Date\((-?\d+)\)\\/')


def dump_json(obj, fp=None, **kwargs):
    """
    Wrapper for ``json.dump(s)`` that uses :class:`JSONDatetimeEncoder`.

    :param obj: Object to dump to JSON.
    :type obj: JSON-encodable (including datetime)
    :param fp: If ``None``, :func:`json.dumps` is called and its value
               returned. If a string, ``fp`` is interpreted as a file path
               and the data will be written to the file at ``fp``. If a
               file-like object, :func:`json.dump` is called. Defaults to
               ``None``.
    :type fp: ``None`` or str or file-like object
    :returns: JSON-encoded ``obj`` if dumping to a string.
    :rtype: str if ``fp`` is ``None``, else ``None``
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
    Wrapper for ``json.load(s)`` that uses :class:`JSONDatetimeDecoder`.

    :param str_or_fp: String or file-like object from which to load.
    :type str_or_fp: str or file-like object
    :returns: Decoded JSON object.
    :rtype: JSON-encodable type (including datetime)
    """
    kwargs.setdefault('cls', JSONDatetimeDecoder)
    if isinstance(str_or_fp, basestring):
        return json.loads(str_or_fp, **kwargs)
    return json.load(str_or_fp, **kwargs)


class JSONDatetimeDecoder(json.JSONDecoder):
    """Datetime-aware JSON decoder."""
    def decode(self, s):
        return self.decode_date(super(JSONDatetimeDecoder, self).decode(s))

    def decode_date(self, value):
        """
        Datetime-aware decoding method.

        If the string value matches the datetime format, it is decoded. Lists
        and dictionaries are examined recursively for datetime formatted
        values. All other values are returned as-is.
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
    """Datetime-aware JSON encoder."""
    def _encode_date(self, date):
        return '\/Date(%i)\/' % int(time.mktime(date.timetuple()) * 1000)

    def _replace_datetime(self, obj):
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

    def _restore_datetime(self, obj, replaced):
        for obj, new_key, old_key in replaced:
            obj[old_key] = obj[new_key]
            del obj[new_key]

    def default(self, obj):
        """
        Turns datetime objects into datetime-formatted strings. If the object
        is not a datetime, this simply calls
        :meth:`json.JSONEncoder.default()`.
        """
        if isinstance(obj, datetime.datetime):
            return self._encode_date(obj)
        return super(JSONDatetimeEncoder, self).default(obj)

    def encode(self, obj, *args, **kwargs):
        superclass = super(JSONDatetimeEncoder, self)
        replaced = self._replace_datetime(obj)
        try:
            return superclass.encode(obj, *args, **kwargs)
        finally:
            self._restore_datetime(obj, replaced)

    def iterencode(self, obj, *args, **kwargs):
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
PBKDF2_DEFAULT_ITERATIONS = 32768

#: Default salt length.
PBKDF2_DEFAULT_SALT_LENGTH = 32

#: Struct used by :func:`pbkdf2`.
pbkdf2_pack_int = struct.Struct('>I').pack


def pbkdf2(data, salt, iterations=1000, keylen=24, codec='base64_codec'):
    """
    Returns PBKDF2/SHA-1 digest for ``data``.

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
    Returns absolute path, with variables and ``~`` expanded.

    :param str path: Path, possibly with variables and ``~``.
    :returns: Absolute path with special sequences expanded.
    :rtype: str
    """
    return os.path.abspath(os.path.expanduser(os.path.expandvars(path)))


def generate_key(password, size, backend=None):
    """
    Generates a key via PBKDF2 and returns key and parameters.

    Returns a 3-tuple containing ``(key, iterations, salt)``.

    :param str password: Password from which to derive the key.
    :param int size: Desired length of the key, in bytes.
    :param str backend: Name of the backend for which to generate the key. If
                        ``--<backend>-pbkdf2-iterations`` and/or
                        ``--<backend>-pbkdf2-salt-length`` was specified, those
                        values will be used. Otherwise
                        :data:`PBKDF2_DEFAULT_ITERATIONS` and
                        :data:`PBKDF2_DEFAULT_SALT_LENGTH` will be used.
    :returns: 3-tuple: ``(key, iterations, salt)``.
    :rtype: tuple
    """
    arg = '%s_pbkdf2_iterations' % backend
    iterations = getattr(args, arg, PBKDF2_DEFAULT_ITERATIONS)
    arg = '%s_pbkdf2_salt_length' % backend
    salt_length = getattr(args, arg, PBKDF2_DEFAULT_SALT_LENGTH)
    salt = binascii.hexlify(random(salt_length))
    return pbkdf2(password, salt, iterations, size), iterations, salt


def get_executable(name):
    """
    Returns the full path to executable named ``name``, if it exists.

    :param str name: Name of the executable to find.
    :returns: Full path to the executable or ``None``.
    :rtype: str or ``None``
    """
    directories = filter(None, os.environ.get('PATH', '').split(os.pathsep))
    for directory in directories:
        path = os.path.join(directory.strip('"'), name)
        if os.path.isfile(path) and os.access(path, os.X_OK):
            return path


def prompt_for_new_password():
    """
    Prompts user for a new password (with confirmation) and returns it.

    :returns: Confirmed user-generated password.
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
    Prompts a user for a password until data is successfully decrytped.

    Assumes that ``fn`` raises a :exc:`SafeCryptographyError` if decryption is
    unsucessful. Returns 2-tuple of ``(password, decrypted data)``.

    :param fn: Function to call to decrypt data. Should take a single argument:
               the password to be used for decryption. If decryption fails, the
               function should raise an exception of the type specified in
               ``cls``.
    :type fn: function(string)
    :param password: Initial password to try. If this fails, no error message
                     will be printed to the console. If ``None``, user is
                     immediately prompted for a password.
    :type password: str or ``None``
    :returns: 2-tuple: ``(password, decrypted data)``.
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
               fails, the function should raise an exception of the type
               specified in ``cls``.
    :type fn: function(string, string)
    :param dict data: Dictionary containing ``data``, ``iterations``, and
                      ``salt`` keys. These should be populated with the
                      encrypted data, the number of PBKDF2 iterations used when
                      encrypting the data, and the PBKDF2 salt used to encrypt
                      the data, respectively.
    :param int key_size: Size of the key used to encrypt the data, in bytes.
    :param password: See :func:`prompt_until_decrypted`.
    :returns: 2-tuple: ``(password, decrypted data)``.
    :rtype: tuple
    """
    def wrapper(password):
        key = pbkdf2(password, data['salt'], data['iterations'], key_size)
        return fn(data['data'], key)
    return prompt_until_decrypted(wrapper, password)


# =============================================================================
# ----- Backend: Base ---------------------------------------------------------
# =============================================================================

#: Dictionary mapping backend names to classes.
backend_map = dict()


def backend(name):
    """
    Class decorator for registering backends. Raises :exc:`NameConflictError`
    if ``name`` has already been registered.

    Example::

        @backend('example')
        class ExampleSafeBackend(SafeBackend):
            \"\"\"Example safe backend.\"\"\"
            ...

    :param str name: Human-friendly name to use for the backend.
    :raises NameConflictError: if ``name`` has already been registered.
    :returns: Class decorated with ``@backend`` (unchanged).
    :rtype: type
    """
    if name in backend_map:
        raise NameConflictError(name)

    def decorator(cls):
        """
        Registers the class with :data:`backend_map` and returns the class.

        :param cls: Backend class.
        :type cls: type
        :rtype: type
        """
        backend_map[name] = cls
        return cls

    return decorator


class SafeBackend(object):
    """
    Base class for safe backends.

    Subclasses should override :meth:`read` and :meth:`write`, and possibly
    :meth:`add_arguments` if they have parameters to add to the command-line.
    See the documentation for those methods for more information.
    """
    @staticmethod
    def add_arguments():
        """
        Adds arguments to the top-level command.

        Subclasses that need to add command-line arguments should implement
        this method and use the global ``parser`` object to do so. Note:

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
        """

    def __init__(self, password=None):
        self.password = password

    def __repr__(self):
        rv = u'<%s>' % self.__class__.__name__
        for name, cls in backend_map.iteritems():
            if cls is self.__class__:
                rv = u'<%s (%s)>' % (self.__class__.__name__, name)
                break
        return rv

    def read(self, path):
        """
        Subclasses must override this method to return decrypted data from
        file at ``path``.

        :param str path: Path to the file containing encrypted data.
        :returns: Decrypted and decoded JSON object.
        :rtype: object
        """
        raise NotImplementedError

    def write(self, path, data):
        """
        Subclasses must override this method to write encrypted ``data`` to
        a file at ``path``.

        :param str path: Path to file where encrypted data should be written.
        :param data: Data to write to ``path``.
        :type data: JSON-encodable data (including datetime)
        """
        raise NotImplementedError


# =============================================================================
# ----- Backend: Bcrypt -------------------------------------------------------
# =============================================================================

#: Full path to the bcrypt executable.
BCRYPT = get_executable('bcrypt')

#: Default number of times to overwrite plaintext files after encryption.
BCRYPT_DEFAULT_OVERWRITES = 7

if BCRYPT:  # pragma: no branch
    @backend('bcrypt')
    class BcryptSafeBackend(SafeBackend):
        """Backend that uses the bcrypt command-line tool."""
        @staticmethod
        def add_arguments():
            parser.add_argument(
                '--bcrypt-overwrites',
                default=BCRYPT_DEFAULT_OVERWRITES,
                help='number of times to overwrite plaintext in file '
                     '(default: %(default)s)',
                metavar='NUMBER',
                type=int,
            )

        def decrypt(self, path, password):
            """
            Decrypts file at ``path`` using ``password``. Immediately
            re-encrypts file after decryption.

            :param str path: Path to the file to decrypt. **Must end in**
                             ``.bfe``.
            :param str password: Password to decrypt file.
            :raises BcryptFilenameError: if filename does not end with
                                         ``.bfe``.
            :raises BcryptCryptographyError: if the bcrypt command has a
                                             nonzero exit.
            :returns: Decrypted file contents.
            :rtype: str
            """
            if not path.endswith('.bfe'):
                raise BcryptFilenameError('filename must end with .bfe')
            process = pexpect.spawn('%s %s' % (BCRYPT, path))
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
            Encrypts file at ``path`` with ``password``. Encrypted filename
            is the original filename plus ``.bfe``.

            :param str path: Path to the file to decrypt. **Must not end in**
                             ``.bfe``.
            :param str password: Password with which to encrypt file.
            :raises BcryptFilenameError: if filename ends with ``.bfe``.
            :raises BcryptCryptographyError: if the bcrypt command has a
                                             nonzero exit.
            """
            if path.endswith('.bfe'):
                raise BcryptFilenameError('path cannot end with .bfe')
            command = '%s -s%i %s' % (BCRYPT, args.bcrypt_overwrites, path)
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

if cryptography_installed:  # pragma: no branch
    @backend('fernet')
    class FernetSafeBackend(SafeBackend):
        """Backend that uses Cryptography's Fernet recipe."""
        KEY_SIZE = 32

        @staticmethod
        def add_arguments():
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

        def decrypt(self, data, key):
            """
            Decrypts ``data`` using ``key``.

            :param str data: Data to decrypt.
            :param str key: Key with which to decrypt ``data``.
            :raises CryptographyError: if data cannot be decrypted.
            :returns: Decrypted data.
            :rtype: str
            """
            try:
                return CryptographyFernet(key).decrypt(bytes(data))
            except CryptographyInvalidToken, e:
                raise CryptographyError(e.message)

        def read(self, path):
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

#: Full path to the gpg2 executable.
GPG = get_executable('gpg2')

#: Default cipher to use.
GPG_DEFAULT_CIPHER = 'cast5'

if GPG:  # pragma: no branch
    @backend('gpg')
    class GPGSafeBackend(SafeBackend):
        """Backend that uses GPG2's command line tools' symmetric ciphers."""
        @staticmethod
        def add_arguments():
            process = pexpect.spawn('%s --version' % GPG)
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
                help='gpg cipher to use (choices: %(choices)s) '
                     '(default: %(default)s)',
                metavar='GPG_CIPHER',
            )

        def decrypt(self, path, password):
            """
            Decrypts file at ``path`` using ``password``.

            :param str path: Path to the file to decrypt.
            :param str password: Password to decrypt file.
            :raises GPGError: if the gpg command has a nonzero exit.
            :returns: Decrypted file contents.
            :rtype: str
            """
            command = ' '.join((
                GPG,
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
                raise GPGError('failed to decrypt safe: %s' % out)
            lines = []
            for line in out.splitlines():
                if not line.startswith('gpg:'):
                    lines.append(line)
            return '\n'.join(lines)

        def read(self, path):
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
            if self.password is None:
                self.password = prompt_for_new_password()
            tmp_directory = tempfile.mkdtemp()
            try:
                tmp = os.path.join(tmp_directory, 'safe.gpg')
                command = ' '.join((
                    GPG,
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
                    raise GPGError('failed to gpg encrypt file: %s' % out)
                os.rename(tmp, path)
            finally:
                shutil.rmtree(tmp_directory)


# =============================================================================
# ----- Backend: NaCl ---------------------------------------------------------
# =============================================================================

if nacl_installed:  # pragma: no branch
    @backend('nacl')
    class NaClSafeBackend(SafeBackend):
        """Backend that uses PyNaCl's SecretBox."""
        #: Nonce used for encryption and decryption. Because we
        #: generate a new random salt (and thus a new key) each time
        #: the data is encrypted, it's cryptographically fine to use
        #: the same nonce.
        NONCE = '0' * 24

        @staticmethod
        def add_arguments():
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

        def decrypt(self, data, key, nonce):
            """
            Decrypts ``data`` using ``key`` and ``nonce``.

            :param str data: Base64-encoded encrypted data.
            :param str key: Base64-encoded key.
            :param str nonce: Nonce used to encrypt the data.
            :raises NaClError: if data cannot be decrypted.
            :returns: Decrypted data.
            :rtype: str
            """
            data, nonce = bytes(data), bytes(nonce)
            box = NaClSecretBox(bytes(key), NaClBase64Encoder)
            try:
                return box.decrypt(data, nonce, NaClBase64Encoder)
            except NaClCryptoError, e:
                raise NaClError(e.message)

        def encrypt(self, data, key, nonce):
            """
            Encrypts ``data`` using ``key`` and ``nonce``.

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
    def read(self, path):
        with open(path) as f:
            return load_json(f)

    def write(self, path, data):
        with open(path, 'w') as f:
            dump_json(data, f)


# =============================================================================
# ----- Application -----------------------------------------------------------
# =============================================================================

#: Envvar containing the backend.
BACKEND_ENVVAR = 'SAFE_BACKEND'

#: Operation canceled by user.
ERR_CANCELED = 10

#: Envvar containing the path to the safe.
PATH_ENVVAR = 'SAFE_PATH'

#: Preferred backends, in priority order.
PREFERRED_BACKENDS = ('gpg', 'bcrypt', 'nacl', 'fernet', 'plaintext')


@app
def safe():
    kwargs = dict(default=None, help='file to read from', required=True)
    if PATH_ENVVAR in os.environ:
        kwargs.update(dict(
            default=os.environ[PATH_ENVVAR],
            help='file to read from (default from %s: %%(default)s)' %
                 PATH_ENVVAR,
            required=False,
        ))
    parser.add_argument(
        '-f',
        '--file',
        **kwargs
    )

    backend_names = sorted(backend_map)
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

    for name in backend_names:
        backend_map[name].add_arguments()

    yield

    g.path = expand_path(args.file)
    g.safe = backend_map[args.backend]()
    try:
        g.data = []
        if os.path.exists(g.path):
            for item in g.safe.read(g.path):
                g.data.append(AttributeDict(item))
        if subcommand() and (g.data or os.path.exists(g.path)):
            g.safe.write(g.path, g.data)
    except KeyboardInterrupt:
        print
        yield ERR_CANCELED


# =============================================================================
# ----- Command: cp -----------------------------------------------------------
# =============================================================================

#: User elected not to overwrite a file.
ERR_CP_OVERWRITE_CANCELED = 20


@safe
def cp():
    """Creates a new safe from an existing one."""
    parser.add_argument(
        'new_file',
        help='file to copy safe to (if not specified, the current safe will '
             'be replaced with the new one)',
        metavar='new-file',
        nargs='?',
    )
    parser.add_argument(
        '-c',
        '--change-password',
        action='store_true',
        default=False,
        help='change password for the safe',
    )

    backend_names = sorted(backend_map)
    parser.add_argument(
        '-b',
        '--backend',
        choices=backend_names,
        dest='new_backend',
        help='crypto backend for the new safe (choices: %(choices)s) '
             '(default: same as current backend)',
        metavar='BACKEND',
    )

    yield

    if args.new_file is None:
        args.new_file = g.path
    path = expand_path(args.new_file)
    if os.path.exists(path):
        while True:
            yn = raw_input('Overwrite %s? [y/N] ' % path).lower()
            if yn and yn[0] not in ('n', 'y'):
                continue
            if yn and yn[0] == 'y':
                break
            yield ERR_CP_OVERWRITE_CANCELED

    g.path = path
    g.safe = backend_map[args.new_backend or args.backend](
        None if args.change_password else g.safe.password,
    )


# =============================================================================
# ----- Command: ls -----------------------------------------------------------
# =============================================================================

@safe
def ls():
    """Lists secrets in the safe."""
    columns = dict(
        created=lambda x: x.created,
        modified=lambda x: sorted(x.vals, reverse=True)[0],
        name=lambda x: x.names[0],
    )

    parser.add_argument(
        '-r',
        '--reverse',
        action='store_true',
        default=False,
        help='sort in reverse order',
    )
    parser.add_argument(
        '-s',
        '--sort',
        choices=sorted(columns.keys()),
        default='name',
        help='value to sort by (choices: %(choices)s) (default: %(default)s)',
        metavar='VALUE',
    )

    yield

    if len(g.data) == 0:
        yield

    rows = []
    for secret in sorted(g.data, key=columns[args.sort], reverse=args.reverse):
        created = secret.created.strftime('%Y-%m-%d')
        modified = sorted(secret.vals, reverse=True)[0].strftime('%Y-%m-%d')
        aliases = ', '.join(secret.names[1:])
        rows.append((secret.names[0], created, modified, aliases))

    column_range = range(0, len(rows[0]))
    row_range = range(0, len(rows))
    widths = [max([len(rows[i][j]) for i in row_range]) for j in column_range]
    fmt = '  '.join(['%%-%is' % width for width in widths])
    for row in rows:
        print fmt % row


# =============================================================================
# ----- Command: new ----------------------------------------------------------
# =============================================================================

@safe
def new():
    """Adds a new secret to the safe."""
    yield
    print 'Not yet implemented'


# =============================================================================
# ----- Command: pb -----------------------------------------------------------
# =============================================================================

# ----- Drivers ---------------------------------------------------------------

#: List of pasteboard driver classes.
pasteboard_drivers = []

#: Absolute path to the ``pbcopy`` executable, or ``None`` if not present.
PBCOPY = get_executable('pbcopy')

#: Absolute path to the ``pbpaste`` executable, or ``None`` if not present.
PBPASTE = get_executable('pbpaste')

#: Absolute path to the ``xclip`` executable, or ``None`` if not present.
XCLIP = get_executable('xclip')


def get_pasteboard_driver():
    """
    Returns the pasteboard driver for this system.

    :returns: :class:`PasteboardDriver` subclass for this system or ``None`` if
              no drivers support this platform.
    :rtype: :class:`PasteboardDriver` or ``None``
    """
    candidates = dict()
    for cls in pasteboard_drivers:
        if cls.supports_platform():
            candidates[cls] = cls.specificity
    if candidates:
        max_specificity = max(candidates.values())
        best_candidates = []
        for cls, specificity in candidates.iteritems():
            if specificity == max_specificity:
                best_candidates.append(cls)
        if len(best_candidates) > 1:
            classes = {cls.__name__.lower(): cls for cls in best_candidates}
            return classes[sorted(classes)[0]]
        return best_candidates[0]


def pasteboard_driver(cls):
    """
    Class decorator for registering pasteboard drivers.

    :param type cls: Class to register.
    :returns: ``cls``, unchanged.
    :rtype: type
    """
    pasteboard_drivers.append(cls)
    return cls


class PasteboardDriver(object):
    """
    Base class for pasteboard drivers.
    """
    #: Subclasses should override this to indicate specificity. If
    #: multiple drivers return ``True`` for :meth:`supports_platform`,
    #: the driver with the highest specificity is used. If multiple
    #: drivers have the same specificity, the class names are sorted
    #: alphabetically and case-insensitively, and the first one is used.
    specificity = 0

    @staticmethod
    def add_arguments():
        """
        Subclasses can override this method to add arguments to the
        :class:`argparse.ArgumentParser` for the ``pb`` command. Unlike
        :class:`SafeBackend` subclasses, drivers should not prefix the
        argument names, since there is only one pasteboard driver active
        at any given time.
        """

    @staticmethod
    def supports_platform():
        """
        Subclasses must override this method to return a boolean indicating
        whether the current system is supported by this driver.

        :returns: Boolean indicating support for this platform.
        :rtype: bool
        """
        raise NotImplementedError

    def read(self):
        """
        Subclasses must override this method to return the data currently
        on the pasteboard.

        :returns: Data currently on the pasteboard.
        :rtype: str
        """
        raise NotImplementedError

    def write(self, data):
        """
        Subclasses must override this method to write data to the pasteboard.

        :param str data: Data to write to the pasteboard.
        """
        raise NotImplementedError


@pasteboard_driver
class PbcopyPasteboardDriver(PasteboardDriver):
    """
    Pasteboard driver that uses the ``pbcopy`` and ``pbpaste`` commands found
    on OS X.
    """
    specificity = 10

    @staticmethod
    def add_arguments():
        parser.add_argument(
            '-p',
            '--pasteboard',
            choices=('find', 'font', 'general', 'ruler'),
            default='general',
            help='pasteboard to use (choices: %(choices)s) (default: '
                 '%(default)s)',
            metavar='PASTEBOARD',
        )

    @staticmethod
    def supports_platform():
        return PBCOPY and PBPASTE

    def read(self):
        cmd = '%s -pboard %s -Prefer txt' % (PBPASTE, args.pasteboard)
        process = pexpect.spawn(cmd)
        rv = process.read()
        process.close()
        return rv

    def write(self, data):
        cmd = (PBCOPY, '-pboard', args.pasteboard)
        process = subprocess.Popen(cmd, stdin=subprocess.PIPE)
        process.communicate(data)
        process.wait()
        return process.returncode


@pasteboard_driver
class XclipPasteboardDriver(PasteboardDriver):
    """
    Pasteboard driver that uses the ``xclip`` command, commonly available on
    Linux.
    """
    specificity = 5

    @staticmethod
    def add_arguments():
        parser.add_argument(
            '-p',
            '--pasteboard',
            choices=('clipboard', 'primary', 'secondary'),
            default='clipboard',
            help='pasteboard to use (choices: %(choices)s) (default: '
                 '%(default)s)',
            metavar='PASTEBOARD',
        )

    @staticmethod
    def supports_platform():
        return XCLIP

    def read(self):
        cmd = '%s -selection %s -o' % (XCLIP, args.pasteboard)
        process = pexpect.spawn(cmd)
        rv = process.read()
        process.close()
        return rv

    def write(self, data):
        cmd = (XCLIP, '-selection', args.pasteboard)
        process = subprocess.Popen(cmd, stdin=subprocess.PIPE)
        process.communicate(data)
        process.wait()
        time.sleep(0.1)
        return process.returncode


# ----- Command ---------------------------------------------------------------

#: Unsupported platform.
ERR_PB_UNSUPPORTED_PLATFORM = 60

#: User supplied an invalid time.
ERR_PB_INVALID_TIME = 61

#: No items matching the name given.
ERR_PB_NO_MATCH = 62

#: Failed to put secret on the pasteboard.
ERR_PB_PUT_SECRET_FAILED = 63

#: Failed to clear the secret from the pasteboard.
ERR_PB_PUT_GARBAGE_FAILED = 64


@safe
def pb():
    """Copies a secret to the pasteboard temporarily."""
    driver_class = get_pasteboard_driver()
    if driver_class is not None:
        driver_class.add_arguments()

    parser.add_argument(
        'name',
        nargs=1,
        help='name of the secret to copy to the pasteboard',
    )
    parser.add_argument(
        '-t',
        '--time',
        default=5,
        help='seconds to keep secret on pasteboard (default: %(default)s)',
        type=float,
    )

    yield

    if driver_class is None:
        print >> sys.stderr, 'error: no pasteboard support for your platform'
        yield ERR_PB_UNSUPPORTED_PLATFORM

    if args.time < 0.1:
        print >> sys.stderr, 'error: time must be >= 0.1: %s' % args.time
        yield ERR_PB_INVALID_TIME

    for item in g.data:
        if args.name[0] in item.names:
            secret = item.vals[sorted(item.vals, reverse=True)[0]]
            break
    else:
        print >> sys.stderr, 'error: no secret with name: %s' % args.name[0]
        yield ERR_PB_NO_MATCH

    pasteboard = driver_class()
    if pasteboard.write(secret):
        print >> sys.stderr, 'error: failed to copy secret to pasteboard'
        yield ERR_PB_PUT_SECRET_FAILED

    line_fmt = 'secret on pasteboard for %0.1fs...'
    line = ''
    try:
        i = args.time
        while i > 0:
            sys.stdout.write('\r' + ' ' * len(line) + '\r')
            line = line_fmt % i
            sys.stdout.write(line)
            sys.stdout.flush()
            time.sleep(0.1)
            i -= 0.1
    finally:
        if pasteboard.write('x'):
            msg = 'error: failed to clear secret from the pasteboard'
            print >> sys.stderr, msg
            yield ERR_PB_PUT_GARBAGE_FAILED

        sys.stdout.write('\r' + ' ' * len(line) + '\r')
        print 'pasteboard cleared'


# =============================================================================
# ----- Command: sh -----------------------------------------------------------
# =============================================================================

@safe
def sh():
    """Opens an interactive shell prompt."""
    yield
    print 'Not yet implemented'


# =============================================================================
# ----- Command: up -----------------------------------------------------------
# =============================================================================

@safe
def up():
    """Starts an interactive session to update old passwords."""
    yield
    print 'Not yet implemented'


if __name__ == '__main__':  # pragma: no cover
    safe.main()
