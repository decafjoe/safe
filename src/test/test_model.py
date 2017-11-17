# -*- coding: utf-8 -*-
"""
Tests for :mod:`safe.model`.

:author: Joe Joyce <joe@decafjoe.com>
:copyright: Copyright (c) Joe Joyce and contributors, 2016-2017.
:license: BSD
"""
import pytest

from safe.model import Account, Alias, Policy, Question


def test():
    """Check slug validation for models."""
    valid_values = ('a', 'foo', 'asdf-fdsa', 'bar/baz', 'hello_there-silly')
    invalid_values = ('', 'a' * 21, 'a@b', 'not good')
    parameters = (
        (Account, 'name'),
        (Alias, 'value'),
        (Policy, 'name'),
        (Question, 'identifier'),
    )
    for model, attribute_name in parameters:
        model()
        for value in valid_values:
            model(**{attribute_name: value})
        for value in invalid_values:
            with pytest.raises(AssertionError):
                model(**{attribute_name: value})
        instance = model()
        for value in valid_values:
            setattr(instance, attribute_name, value)
        for value in invalid_values:
            with pytest.raises(AssertionError):
                setattr(instance, attribute_name, value)
