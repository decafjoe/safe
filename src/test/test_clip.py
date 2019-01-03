# -*- coding: utf-8 -*-
"""
Tests for :mod:`safe.clip`.

:author: Joe Joyce <joe@decafjoe.com>
:copyright: Copyright (c) Joe Joyce and contributors, 2016-2019.
:license: BSD
"""
import mock
import pytest
from clik.argparse import ArgumentParser

from safe.clip import clipboard_drivers, ClipboardError, Driver, Pasteboard, \
    Registry, sorted_by_precedence, Xclip


def test_sorted_by_precedence():
    """Check that precedence sorts come back in the right order."""
    class Dummy(object):
        def __init__(self, precedence):
            self.precedence = precedence

    d_0 = Dummy(0)
    d_10 = Dummy(10)
    d_100 = Dummy(100)
    d_minus_42 = Dummy(-42)

    unordered = [d_100, d_10, d_minus_42, d_0]
    ordered = [d_100, d_10, d_0, d_minus_42]
    assert sorted_by_precedence(unordered) == ordered


def test_registry():
    """Check registry operations."""
    drivers = Registry()

    class A(object):
        name = 'a'
        precedence = 10
        supported = True

    class B(object):
        name = 'b'
        precedence = 10
        supported = False

    class C(object):
        name = 'c'
        precedence = 20
        supported = True

    assert drivers.register(A) is A
    assert drivers.register(B) is B
    assert drivers.register(C) is C

    assert drivers.supported == [C, A]
    assert drivers.preferred is C

    with pytest.raises(ClipboardError) as ei:
        drivers.register(A)
    e = ei.value
    assert 'driver "a" already registered' in str(e)


def test_empty_registry():
    """Check that error is raised on configure parser on empty registry."""
    drivers = Registry()
    with pytest.raises(ClipboardError) as ei:
        drivers.configure_parser(None)
    e = ei.value
    assert 'no supported clipboards' == str(e)


def test_empty_driver():
    """Check attributes of a basically undefined driver."""
    class Bad(Driver):
        pass

    driver = Bad()
    assert driver.param == {}
    with pytest.raises(NotImplementedError):
        driver.get()
    with pytest.raises(NotImplementedError):
        driver.put('hai')


def test_params():
    """Check parameter handling in the context of set/unset defaults."""
    class No(Driver):
        pass

    class NoDefault(Driver):
        parameters = dict(example={})

    class Default(Driver):
        parameters = dict(example=dict(default='foo'))

    assert No().param == {}
    assert No(example='bar').param == dict(example='bar')
    assert NoDefault().param == {}
    assert NoDefault(example='bar').param == dict(example='bar')
    assert Default().param == dict(example='foo')
    assert Default(example='bar').param == dict(example='bar')


@pytest.mark.skipif(not Pasteboard.supported, reason='requires pbcopy/pbpaste')
def test_pasteboard():
    """Check macOS pasteboard driver."""
    general = Pasteboard()
    general.put('hai')
    assert general.get() == 'hai'
    general.put('hello')
    assert general.get() == 'hello'

    text = Pasteboard(board='text')
    text.put('hai')
    assert text.get() == 'hai'
    text.put('hello')
    assert text.get() == 'hello'


def test_pasteboard_failure():
    """Check that (mocked) failure raises an exception."""
    with mock.patch('safe.clip.run') as run:
        run.return_value = 1, 'foo', 'bar'

        with pytest.raises(ClipboardError) as ei:
            Pasteboard().get()
        e = ei.value
        assert 'failed with stderr: bar' in str(e)

        with pytest.raises(ClipboardError) as ei:
            Pasteboard().put('hai')
        e = ei.value
        assert 'failed with stderr: bar' in str(e)


# @pytest.mark.skipif(not Xclip.supported, reason='requires xclip')
@pytest.mark.skipif(True, reason='xclip tests require display')
def test_xclip():
    """Check Xclip driver."""
    clipboard = Xclip()
    clipboard.put('hai')
    assert clipboard.get() == 'hai'
    clipboard.put('hello')
    assert clipboard.get() == 'hello'


def test_xclip_failure():
    """Check that (mocked) failure raises an exception."""
    with mock.patch('safe.clip.run') as run:
        run.return_value = 1, 'foo', 'bar'

        with pytest.raises(ClipboardError) as ei:
            Xclip().get()
        e = ei.value
        assert 'failed with stderr: bar' in str(e)

        with pytest.raises(ClipboardError) as ei:
            Xclip().put('hai')
        e = ei.value
        assert 'failed with stderr: bar' in str(e)


# @pytest.mark.skipif(not clipboard_drivers.supported,
#                     reason='requires clipboard')
@pytest.mark.skipif(not clipboard_drivers.supported or
                    clipboard_drivers.preferred is Xclip,
                    reason='no supported drivers, or driver is xclip')
def test_defult_clipboard():
    """Check default clipboard as a way of indirectly testing parser/args."""
    parser = ArgumentParser()
    clipboard_drivers.configure_parser(parser)
    print(parser.parse_args(()))
    clipboard = clipboard_drivers.driver_for_args(parser.parse_args(()))
    clipboard.put('hai')
    assert clipboard.get() == 'hai'
    clipboard.put('hello')
    assert clipboard.get() == 'hello'
