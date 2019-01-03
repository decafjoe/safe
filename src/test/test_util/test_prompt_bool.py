# -*- coding: utf-8 -*-
"""
Tests for :func:`safe.util.prompt_bool`.

:author: Joe Joyce <joe@decafjoe.com>
:copyright: Copyright (c) Joe Joyce and contributors, 2016-2019.
:license: BSD
"""
import mock
import pytest

from safe.util import prompt_bool


@pytest.mark.parametrize('default,expected,values', (
    (False, False, ('', 'n', 'N', 'foo', 'asdf')),
    (False, True, ('y', 'Y')),
    (True, False, ('n', 'N')),
    (True, True, ('', 'y', 'Y', 'foo', 'asdf')),
))
def test(default, expected, values):
    """Check various combinations of defaults and values."""
    for value in values:
        with mock.patch('safe.util.input') as input:
            input.return_value = value
            assert expected == prompt_bool('', default)
