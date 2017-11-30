# -*- coding: utf-8 -*-
"""
Tests for :mod:`safe.sgen`.

:author: Joe Joyce <joe@decafjoe.com>
:copyright: Copyright (c) Joe Joyce and contributors, 2016-2017.
:license: BSD
"""
import string

import pytest

from safe.sgen import generate, generator, UnsurmountableConstraints


def test_generator():
    orig = generate.copy()
    generate.clear()
    try:
        assert not generate

        @generator('foo')
        def foo():
            pass

        @generator('bar', default=True)
        def bar():
            pass

        assert len(generate) == 3
        assert generate.foo is foo
        assert generate.bar is bar
        assert generate.default is bar
    finally:
        generate.update(orig)


def test_random_generator_no_characters():
    with pytest.raises(UnsurmountableConstraints) as ei:
        generate.random(1, string.printable)
    e = ei.value
    assert str(e) == 'no characters to choose from'


def test_random_generator():
    disallowed = 'abc123'
    generated = []
    for _ in range(2 ** 10):
        value = generate.random(32, disallowed)
        for char in disallowed:
            assert char not in value
        assert value not in generated
        generated.append(value)
