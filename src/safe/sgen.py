# -*- coding: utf-8 -*-
"""
Secret generators.

:author: Joe Joyce <joe@decafjoe.com>
:copyright: Copyright (c) Joe Joyce and contributors, 2016-2017.
:license: BSD
"""
import random
import string

from clik.util import AttributeDict

generate = AttributeDict()


def generator(name, default=False):
    def decorator(fn):
        generate[name] = fn
        if default:
            generate.default = fn
        return fn
    return decorator


@generator('random', default=True)
def random_characters(length):
    choice = random.SystemRandom().choice
    characters = string.digits \
                 + string.ascii_lowercase \
                 + string.ascii_uppercase \
                 + string.punctuation  # noqa: E127
    return ''.join([choice(characters) for _ in range(length)])
