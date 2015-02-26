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

from clik import app, args, parser
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


class SafeError(Exception):
    """Base class for all exceptions raised from this module."""


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
    def default(self, obj):
        """
        Turns datetime objects into datetime-formatted strings. If the object
        is not a datetime, this simply calls
        :meth:`json.JSONEncoder.default()`.
        """
        if isinstance(obj, datetime.datetime):
            return '\/Date(%i)\/' % int(time.mktime(obj.timetuple()) * 1000)
        return super(JSONDatetimeEncoder, self).default(obj)


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


def prompt_until_decrypted(fn, cls, password=None):
    """
    Prompts a user for a password until data is successfully decrytped.

    Returns 2-tuple of ``(password, decrypted data)``.

    :param fn: Function to call to decrypt data. Should take a single argument:
               the password to be used for decryption. If decryption fails, the
               function should raise an exception of the type specified in
               ``cls``.
    :type fn: function(string)
    :param Exception cls: Class of the exception that is raised when decryption
                          fails.
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
        except cls:
            if prompt_for_password:
                print >> sys.stderr, 'error: failed to decrypt safe'
            password = None


def prompt_until_decrypted_pbkdf2(fn, cls, data, key_size, password=None):
    """
    Wrapper for :func:`prompt_until_decrypted` for backends that use PBKDF2.

    :param fn: Function to call to decrypt data. Should take two arguments:
               a string containing the data to be decrypted and a string
               containing the key, generated from PBKDF2. If decryption
               fails, the function should raise an exception of the type
               specified in ``cls``.
    :type fn: function(string, string)
    :param cls: See :func:`prompt_until_decrypted`.
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
    return prompt_until_decrypted(wrapper, cls, password)


# =============================================================================
# ----- Backend: Base ---------------------------------------------------------
# =============================================================================

#: Dictionary mapping backend names to classes.
backend_map = dict()


def backend(name):
    """
    Class decorator for registering backends. Raises :exc:`SafeError` if
    ``name`` has already been registered.

    Example::

        @backend('example')
        class ExampleSafeBackend(SafeBackend):
            \"\"\"Example safe backend.\"\"\"
            ...

    :param str name: Human-friendly name to use for the backend.
    :returns: Class decorated with ``@backend`` (unchanged).
    :rtype: type
    """
    if name in backend_map:
        raise SafeError('Backend named "%s" already exists' % name)

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

    If subclasses override :meth:`__init__`, they should make sure to call
    the ``__init__`` method defined in this base class.

    Example::

        class ExampleSafeBackend(SafeBackend):
            def __init__(self, *args, **kwargs):
                super(ExampleSafeBackend, self).__init__(*args, **kwargs)

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
    class BcryptError(Exception):
        """Raised when bcrypt encounters an error."""

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

        def __init__(self, *args, **kwargs):
            super(BcryptSafeBackend, self).__init__(*args, **kwargs)
            self._pexpect_spawn = pexpect.spawn
            self._prompt_for_new_password = prompt_for_new_password

        def decrypt(self, path, password):
            """
            Decrypts file at ``path`` using ``password``. Immediately
            re-encrypts file after decryption.

            :param str path: Path to the file to decrypt. **Must end in**
                             ``.bfe``.
            :param str password: Password to decrypt file.
            :raises BcryptError: if filename does not end with ``.bfe``.
            :raises BcryptError: if the file cannot be decrypted.
            :returns: Decrypted file contents.
            :rtype: str
            """
            if not path.endswith('.bfe'):
                raise BcryptError('filename must end with .bfe')
            process = self._pexpect_spawn('%s %s' % (BCRYPT, path))
            process.expect('Encryption key:', timeout=5)
            process.sendline(password)
            out = process.read()
            process.close()
            if process.exitstatus:
                raise BcryptError('failed to decrypt file: %s' % out)
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
            :raises BcryptError: if filename ends with ``.bfe``.
            :raises BcryptError: if the bcrypt command has a nonzero exit.
            """
            if path.endswith('.bfe'):
                raise BcryptError('path cannot end with .bfe')
            command = '%s -s%i %s' % (BCRYPT, args.bcrypt_overwrites, path)
            process = self._pexpect_spawn(command)
            process.expect('Encryption key:', timeout=5)
            process.sendline(password)
            process.expect('Again:', timeout=5)
            process.sendline(password)
            out = process.read()
            process.close()
            if process.exitstatus:
                raise BcryptError('failed to encrypt file: %s' % out)

        def read(self, path):
            tmp_directory = tempfile.mkdtemp()
            try:
                tmp = os.path.join(tmp_directory, 'safe.bfe')
                shutil.copy(path, tmp)
                self.password, rv = prompt_until_decrypted(
                    functools.partial(self.decrypt, tmp),
                    BcryptError,
                    self.password,
                )
                return rv
            finally:
                shutil.rmtree(tmp_directory)

        def write(self, path, data):
            if self.password is None:
                self.password = self._prompt_for_new_password()
                msg = 'error: bcrypt passphrases must be 8 to 56 characters'
                while not 7 < len(self.password) < 57:
                    print >> sys.stderr, msg
                    self.password = self._prompt_for_new_password()
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

        def __init__(self, *args, **kwargs):
            super(FernetSafeBackend, self).__init__(*args, **kwargs)
            self._prompt_for_new_password = prompt_for_new_password

        def read(self, path):
            with open(path) as f:
                data = load_json(f)
            self.password, rv = prompt_until_decrypted_pbkdf2(
                lambda data, key: CryptographyFernet(key).decrypt(bytes(data)),
                CryptographyInvalidToken,
                data,
                self.KEY_SIZE,
                self.password,
            )
            return rv

        def write(self, path, data):
            if self.password is None:
                self.password = self._prompt_for_new_password()
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
    class GPGError(SafeError):
        """Raised for errors originating from GPG."""

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

        def __init__(self, *args, **kwargs):
            super(GPGSafeBackend, self).__init__(*args, **kwargs)
            self._pexpect_spawn = pexpect.spawn
            self._prompt_for_new_password = prompt_for_new_password

        def decrypt(self, path, password):
            """
            Decrypts file at ``path`` using ``password``.

            :param str path: Path to the file to decrypt.
            :param str password: Password to decrypt file.
            :raises GPGError: if the file cannot be decrypted.
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
            process = self._pexpect_spawn(command)
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
                    GPGError,
                    self.password,
                )
            finally:
                shutil.rmtree(tmp_directory)
            return rv

        def write(self, path, data):
            if self.password is None:
                self.password = self._prompt_for_new_password()
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
                process = self._pexpect_spawn(command)
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

        def __init__(self, *args, **kwargs):
            super(NaClSafeBackend, self).__init__(*args, **kwargs)
            self._prompt_for_new_password = prompt_for_new_password

        def decrypt(self, data, key, nonce):
            """
            Decrypts ``data`` using ``key`` and ``nonce``.

            :param str data: Base64-encoded encrypted data.
            :param str key: Base64-encoded key.
            :param str nonce: Nonce used to encrypt the data.
            :raises NaClCryptoError: if data cannot be decrypted.
            :returns: Decrypted data if successful.
            :rtype: str
            """
            box = NaClSecretBox(bytes(key), NaClBase64Encoder)
            return box.decrypt(bytes(data), bytes(nonce), NaClBase64Encoder)

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
                NaClCryptoError,
                data,
                NaClSecretBox.KEY_SIZE,
                self.password,
            )
            return rv

        def write(self, path, data):
            if self.password is None:
                self.password = self._prompt_for_new_password()
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

#: Preferred backends, in priority order.
PREFERRED_BACKENDS = ('gpg', 'bcrypt', 'nacl', 'fernet', 'plaintext')


@app
def safe():
    backend_names = sorted(backend_map)
    for name in PREFERRED_BACKENDS:
        if name in backend_names:
            default_backend_name = name
            break

    parser.add_argument(
        '-b',
        '--backend',
        choices=backend_names,
        default=default_backend_name,
        help='crypto backend to use (choices: %(choices)s) '
             '(default: %(default)s)',
        metavar='BACKEND',
    )
    parser.add_argument(
        '-f',
        '--file',
        help='file to read from',
    )

    for name in backend_names:
        backend_map[name].add_arguments()

    yield


# =============================================================================
# ----- Command: cp -----------------------------------------------------------
# =============================================================================

@safe
def cp():
    """Copies a safe from one location (or backend) to another."""
    yield
    print 'Not yet implemented'


# =============================================================================
# ----- Command: ls -----------------------------------------------------------
# =============================================================================

@safe
def ls():
    """Lists items in the safe."""
    yield
    print 'Not yet implemented'


# =============================================================================
# ----- Command: new ----------------------------------------------------------
# =============================================================================

@safe
def new():
    """Adds a new item to the safe."""
    yield
    print 'Not yet implemented'


# =============================================================================
# ----- Command: pb -----------------------------------------------------------
# =============================================================================

@safe
def pb():
    """Copies a secret to the pasteboard temporarily."""
    yield
    print 'Not yet implemented'


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
