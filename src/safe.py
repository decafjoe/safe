import binascii
import datetime
import getpass
import hashlib
import hmac
import itertools
import json
import operator
import os
import re
import struct
import sys
import tempfile
import time

from clik import app, args, parser

random = None
try:
    from nacl.encoding import Base64Encoder as NaClBase64Encoder
    from nacl.exceptions import CryptoError as NaClCryptoError
    from nacl.secret import SecretBox as NaClSecretBox
    from nacl.utils import random  # noqa
    nacl_installed = True
except ImportError:  # pragma: no cover
    nacl_installed = False

if random is None:  # pragma: no cover
    random = os.urandom


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
    :type fp: None or string or file-like object
    :rtype: string if ``fp`` is ``None``, else ``None``
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
    :type str_or_fp: string or file-like object
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
        """Turns datetime objects into datetime-formatted strings."""
        if isinstance(obj, datetime.datetime):
            return '\/Date(%i)\/' % int(time.mktime(obj.timetuple()) * 1000)
        return super(JSONDatetimeEncoder, self).default(obj)


# =============================================================================
# ----- Utilities -------------------------------------------------------------
# =============================================================================

def prompt_for_new_password():
    while True:
        password = getpass.getpass('New password: ')
        confirm = getpass.getpass('Confirm new password: ')
        if password == confirm:
            return password
        print >> sys.stderr, 'error: passwords did not match'


# =============================================================================
# ----- PBKDF2 ----------------------------------------------------------------
# =============================================================================

pbkdf2_pack_int = struct.Struct('>I').pack


def pbkdf2(data, salt, iterations=1000, keylen=24, codec='base64_codec'):
    """
    Returns base64 encoded PBKDF2/SHA-1 digest for ``data``.

    From https://github.com/mitsuhiko/python-pbkdf2/.

    :param data: Password from which to derive a key.
    :type data: string
    :type salt: Salt.
    :param iterations: Number of pbkdf2 iterations to do. Defaults to
                       ``1000``.
    :type iterations: int
    :param keylen: Desired key length, in bytes. Defaults to ``24``.
    :type keylen: int
    :param codec: Codec to use to encode return value. Defaults to
                  ``'base64_codec'``.
    :type codec: string
    :return: PBKDF2/SHA1 digest encoded
    :rtype: string
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
# ----- Backend: Base ---------------------------------------------------------
# =============================================================================

#: Dictionary mapping backend names to classes.
backend_map = dict()


def backend(name):
    """
    Class decorator for registering backends. Raises :class:`SafeError` if
    ``name`` has already been registered.

    :param name: Human-friendly name to use for the backend.
    :type name: string
    :rtype: class decorator
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
    :meth:`add_arguments` if it has parameters to add to the command-line.
    See the documentation for those methods for more information.
    """
    def __repr__(self):
        rv = u'<%s>' % self.__class__.__name__
        for name, cls in backend_map.iteritems():
            if cls is self.__class__:
                rv = u'<%s (%s)>' % (self.__class__.__name__, name)
                break
        return rv

    @staticmethod
    def add_arguments():
        """
        Adds arguments to the top-level command.

        Subclasses that need to add command-line arguments should implement
        this method and use the global ``parser`` object to do so. There are
        a few caveats:

        * Required arguments *must* be avoided; the user may not actually be
          using this backend.
        * Short arguments *should* be avoided in order to steer clear of
          conflicting option names.
        * Argument names should be prefixed with the class' name as registered
          with the :func:`backend` decorator.

        Example::

            @backend('example')
            class ExampleSafeBackend(SafeBackend):
                @classmethod
                def add_arguments(cls):
                    parser.add_argument(
                        '--example-option',
                        help="this sets `option' for the example backend",
                    )
        """

    def read(self, path):
        """
        Subclasses must override this method to return decrypted data from
        file at ``path``.

        :param path: Path to the file containing encrypted data.
        :type path: string
        :rtype: object
        """
        raise NotImplementedError

    def write(self, path, data):
        """
        Subclasses must override this method to write encrypted ``data`` to
        a file at ``path``.

        :param path: Path to file where encrypted data should be written.
        :type path: string
        :param data: Data to write to ``path``.
        :type data: JSON-encodable data
        """
        raise NotImplementedError


# =============================================================================
# ----- Backend: NaCl ---------------------------------------------------------
# =============================================================================

if nacl_installed:  # pragma: no branch
    @backend('nacl')
    class NaClSafeBackend(SafeBackend):
        """Backend that uses PyNaCl's SecretBox."""
        @classmethod
        def add_arguments(cls):
            parser.add_arguments(
                '--nacl-pbkdf2-iterations',
                default=32768,
                help='number of iterations for PBKDF2 (default: %(default)s)',
                type=int,
            )
            parser.add_arguments(
                '--nacl-pbkdf2-salt-length',
                default=32,
                help='salt length for PBKDF2 (bytes) (default: %(default)s)',
                type=int,
            )

        def __init__(self):
            self._nonce = -1
            self._password = None

            # This is used for testing.
            self._prompt_for_new_password = prompt_for_new_password

        def decrypt(self, data, key, nonce):
            box = NaClSecretBox(bytes(key), NaClBase64Encoder)
            return box.decrypt(bytes(data), bytes(nonce), NaClBase64Encoder)

        def encrypt(self, data, key, nonce):
            box = NaClSecretBox(bytes(key), NaClBase64Encoder)
            message = box.encrypt(bytes(data), bytes(nonce), NaClBase64Encoder)
            return message.ciphertext

        def read(self, path):
            with open(path) as f:
                metadata = load_json(f)
            data = metadata['data']
            iterations = metadata['iterations']
            nonce = metadata['nonce']
            salt = metadata['salt']
            size = NaClSecretBox.KEY_SIZE
            self._nonce = int(nonce)
            while True:
                prompt_for_password = self._password is None
                if prompt_for_password:
                    self._password = getpass.getpass('Password: ')
                key = pbkdf2(self._password, salt, iterations, size)
                try:
                    return load_json(self.decrypt(data, key, nonce))
                except NaClCryptoError:
                    if prompt_for_password:
                        print >> sys.stderr, 'error: failed to decrypt safe'
                    self._password = None

        def write(self, path, data):
            if self._password is None:
                self._password = self._prompt_for_new_password()
            self._nonce += 1
            iterations = args.nacl_pbkdf2_iterations
            nonce = '%%0%ix' % NaClSecretBox.NONCE_SIZE % self._nonce
            salt = binascii.hexlify(random(args.nacl_pbkdf2_salt_length))
            size = NaClSecretBox.KEY_SIZE
            key = pbkdf2(self._password, salt, iterations, size)
            metadata = dict(
                data=self.encrypt(dump_json(data), key, nonce),
                iterations=iterations,
                nonce=nonce,
                salt=salt,
            )
            dump_json(metadata, path)


# =============================================================================
# ----- Backend: Plaintext ----------------------------------------------------
# =============================================================================

@backend('plaintext')
class PlaintextSafeBackend(SafeBackend):
    """Not an actual safe."""
    def read(self, path):
        with open(path) as f:
            return load_json(f)

    def write(self, path, data):
        with open(path, 'w') as f:
            dump_json(data, f)


# =============================================================================
# ----- Application -----------------------------------------------------------
# =============================================================================

@app
def safe():
    yield
    print 'Hello, world!'


if __name__ == '__main__':  # pragma: no cover
    safe.main()
