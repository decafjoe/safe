# -*- coding: utf-8 -*-
"""
Tests for :mod:`safe.model`.

:author: Joe Joyce <joe@decafjoe.com>
:copyright: Copyright (c) Joe Joyce and contributors, 2016-2019.
:license: BSD
"""
import pytest

from safe.model import Account, Alias, Policy, Question

from test import memory_db  # noqa: I100


slug_fields = (
    (Account, 'name'),
    (Alias, 'value'),
    (Policy, 'name'),
    (Question, 'identifier'),
)


@pytest.mark.parametrize('model,field', slug_fields)
@pytest.mark.parametrize('value', [
    'a', 'foo', 'asdf-fdsa', 'bar/baz', 'hello_there-silly',
])
def test_valid_slug_values(model, field, value):
    """Check valid slug values for model constructors and instances."""
    assert model(**{field: value})
    setattr(model(), field, value)


@pytest.mark.parametrize('model,field', slug_fields)
@pytest.mark.parametrize('value', ['', 'a' * 21, 'a@b', 'not good'])
def test_invalid_slug_values(model, field, value):
    """Check invalid slug values for model constructors and instances."""
    with pytest.raises(AssertionError):
        model(**{field: value})
    with pytest.raises(AssertionError):
        setattr(model(), field, value)


@memory_db
def test_account_query_by_slug(db):
    """Check for_slug methods on the account model."""
    foo = Account(name='foo')
    bar = Account(name='bar')
    db.add(foo)
    db.add(bar)
    db.commit()
    db.expire_all()
    db.add(Alias(account_id=bar.id, value='baz'))
    db.commit()
    db.expire_all()
    assert Account.for_slug('foo') is foo
    assert Account.for_slug('bar') is bar
    assert Account.for_slug('baz') is bar
    assert Account.id_for_slug('foo') == foo.id
    assert Account.id_for_slug('bar') == bar.id
    assert Account.id_for_slug('baz') == bar.id


@memory_db
def test_policy_query_by_name(db):
    """Check for_name methods on the policy model."""
    foo = Policy(name='foo')
    bar = Policy(name='bar')
    db.add(foo)
    db.add(bar)
    db.commit()
    db.expire_all()
    assert Policy.for_name('foo') is foo
    assert Policy.for_name('bar') is bar
    assert Policy.id_for_name('foo') == foo.id
    assert Policy.id_for_name('bar') == bar.id


def test_policy_generate_secret():
    """Check secret generator convenience method."""
    policy = Policy(
        disallowed_characters='abc123',
        length=64,
        generator='random',
    )
    for _ in range(2 ** 8):
        value = policy.generate_secret()
        assert len(value) == 64
        for c in 'abc123':
            assert c not in value


@pytest.mark.parametrize('value', [0, 1, 2, 42])
def test_valid_policy_frequency_values(value):
    """Check valid policy frequency values in constructor and instance."""
    assert Policy(frequency=value)
    setattr(Policy(), 'frequency', value)


@pytest.mark.parametrize('value', [-42, -1])
def test_invalid_policy_frequency_values(value):
    """Check invalid policy frequency values in constructor and instance."""
    with pytest.raises(AssertionError):
        assert Policy(frequency=value)
    with pytest.raises(AssertionError):
        setattr(Policy(), 'frequency', value)


@pytest.mark.parametrize('value', ['default', 'random'])
def test_valid_policy_generator_values(value):
    """Check valid policy generator values in constructor and instance."""
    assert Policy(generator=value)
    setattr(Policy(), 'venerator', value)


@pytest.mark.parametrize('value', ['foo', 'not a generator'])
def test_invalid_policy_generator_values(value):
    """Check invalid policy generator values in constructor and instance."""
    with pytest.raises(AssertionError):
        assert Policy(generator=value)
    with pytest.raises(AssertionError):
        setattr(Policy(), 'generator', value)


@pytest.mark.parametrize('value', [1, 2, 42])
def test_valid_policy_length_values(value):
    """Check valid policy length values in constructor and instance."""
    assert Policy(length=value)
    setattr(Policy(), 'length', value)


@pytest.mark.parametrize('value', [0, -42, -1])
def test_invalid_policy_length_values(value):
    """Check invalid policy length values in constructor and instance."""
    with pytest.raises(AssertionError):
        assert Policy(length=value)
    with pytest.raises(AssertionError):
        setattr(Policy(), 'length', value)
