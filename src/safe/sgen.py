# -*- coding: utf-8 -*-
"""
Secret generator API.

:author: Joe Joyce <joe@decafjoe.com>
:copyright: Copyright (c) Joe Joyce and contributors, 2016-2018.
:license: BSD
"""
import random
import string

from clik.util import AttributeDict

#: "Registry" for secret generators. Keys are the "friendly" name for
#: the generator and the values are the generator functions.
#:
#: :type: :class:`dict` mapping ``str -> fn(int, str)``
generate = AttributeDict()


def generator(name, default=False):
    """
    Register a generator.

    :param str name: "Friendly" name for the generator
    :param bool default: If ``true`` generator will be the one used when
                         ``generate.default`` is called (defaults to
                         ``False``)
    :return: Decorator that returns the function passed in
    """
    def decorator(fn):
        """Register function (possibly as the default) and return it as-is."""
        generate[name] = fn
        if default:
            generate.default = fn
        return fn
    return decorator


class UnsurmountableConstraints(Exception):
    """Raised when a secret cannot be generated given the constraints."""


@generator('random', default=True)
def random_characters(length, disallowed_characters=''):
    """
    Return secret composed of random printable characters.

    Registered as the ``random`` generator, and also as the ``default``.

    :param int length: Length of secret to generate
    :param str disallowed_chars: Characters that may not be present in the
                                 secret
    :return: Randomly-generated string
    :rtype: :class:`str`
    """
    choice = random.SystemRandom().choice
    characters = string.digits \
                 + string.ascii_lowercase \
                 + string.ascii_uppercase \
                 + string.punctuation  # noqa: E127
    for char in disallowed_characters:
        characters = characters.replace(char, '')
    if len(characters) < 1:
        raise UnsurmountableConstraints('no characters to choose from')
    return ''.join([choice(characters) for _ in range(length)])
