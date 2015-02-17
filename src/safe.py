from datetime import datetime
from hashlib import sha1
from hmac import new as new_hmac
from itertools import izip, starmap
from json import dump as dump_json_to_file, dumps as dump_json_to_string, \
    load as load_json_from_file, loads as load_json_from_string, JSONDecoder, \
    JSONEncoder
from operator import xor
from re import compile as compile_re
from struct import Struct
from time import mktime

from clik import app


__version__ = '0.2'


# =============================================================================
# ----- Crypto ----------------------------------------------------------------
# =============================================================================

pbkdf2_pack_int = Struct('>I').pack


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
    mac = new_hmac(data, None, sha1)

    def _pseudorandom(x, mac=mac):
        hmac = mac.copy()
        hmac.update(x)
        return map(ord, hmac.digest())

    buf = []
    for block in xrange(1, -(-keylen // mac.digest_size) + 1):
        rv = u = _pseudorandom(salt + pbkdf2_pack_int(block))
        for i in xrange(iterations - 1):
            u = _pseudorandom(''.join(map(chr, u)))
            rv = starmap(xor, izip(rv, u))
        buf.extend(rv)
    return ''.join(map(chr, buf))[:keylen].encode(codec).strip()


# =============================================================================
# ----- JSON+Datetime ---------------------------------------------------------
# =============================================================================

date_re = compile_re(r'\\/Date\((-?\d+)\)\\/')


def dump_json(obj, fp=None, **kwargs):
    """
    Wrapper for ``json.dump(s)`` that uses :class:`JSONDatetimeEncoder`.

    :param obj: Object to dump to JSON.
    :type obj: JSON-encodable (including datetime)
    :param fp: If specified, :func:`json.dump` is called. If ``None``,
               :func:`json.dumps` is called. Defaults to ``None``.
    :rtype: string if ``fp`` is ``None``, else ``None``
    """
    kwargs.setdefault('cls', JSONDatetimeEncoder)
    if fp is None:
        return dump_json_to_string(obj, **kwargs)
    return dump_json_to_file(obj, fp, **kwargs)


def load_json(str_or_fp, **kwargs):
    """
    Wrapper for ``json.load(s)`` that uses :class:`JSONDatetimeDecoder`.

    :param str_or_fp: String or file-like object from which to load.
    :type str_or_fp: string or file-like object
    :rtype: JSON-encodable type (including datetime)
    """
    kwargs.setdefault('cls', JSONDatetimeDecoder)
    if isinstance(str_or_fp, basestring):
        return load_json_from_string(str_or_fp, **kwargs)
    return load_json_from_file(str_or_fp, **kwargs)


class JSONDatetimeDecoder(JSONDecoder):
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
                return datetime.fromtimestamp(timestamp / 1000)
        elif isinstance(value, list):
            return [decode(v) for v in value]
        elif isinstance(value, dict):
            return dict([(decode(k), decode(v)) for k, v in value.iteritems()])
        return value


class JSONDatetimeEncoder(JSONEncoder):
    """Datetime-aware JSON encoder."""
    def default(self, obj):
        """Turns datetime objects into datetime-formatted strings."""
        if isinstance(obj, datetime):
            t = int(mktime(obj.timetuple()) * 1000)
            return '\/Date(%i)\/' % t
        return super(JSONDatetimeEncoder, self).default(obj)


# =============================================================================
# ----- Application -----------------------------------------------------------
# =============================================================================

@app
def safe():
    yield
    print 'Hello, world!'


if __name__ == '__main__':  # pragma: no cover
    safe.main()
