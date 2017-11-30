# -*- coding: utf-8 -*-
"""
Tests for forms in :mod:`safe.form.policy`.

:author: Joe Joyce <joe@decafjoe.com>
:copyright: Copyright (c) Joe Joyce and contributors, 2016-2017.
:license: BSD
"""
import pytest
from clik.argparse import ArgumentParser

from safe.form.policy import NewPolicyForm, UpdatePolicyForm
from safe.model import Policy

from test import memory_db  # noqa: I100


def setup_test(db, form_class, *argv):
    policy = Policy(disallowed_characters='abc', name='foo')
    db.add(policy)
    db.add(Policy(name='bar'))
    db.commit()
    db.refresh(policy)

    parser = ArgumentParser()
    form = form_class()
    form.configure_parser(parser)
    args = parser.parse_args(argv)
    if isinstance(form, UpdatePolicyForm):
        valid = form.bind_and_validate(policy, args=args)
    else:
        valid = form.bind_and_validate(args)

    return policy, form, valid


@memory_db
def test_new_policy_with_existing_name(db):
    _, form, valid = setup_test(db, NewPolicyForm, '--name', 'foo')
    assert not valid
    assert len(form.name.errors) == 1
    assert form.name.errors[0] == 'Policy with that name already exists'


@memory_db
def test_new_empty(db):
    _, form, valid = setup_test(db, NewPolicyForm, '--name', 'baz')
    assert valid
    policy = form.create_policy()
    db.commit()
    assert policy.description is None
    assert policy.disallowed_characters == ''
    assert policy.frequency == Policy.DEFAULT_FREQUENCY
    assert policy.generator == Policy.DEFAULT_GENERATOR
    assert policy.length == Policy.DEFAULT_LENGTH
    assert policy.name == 'baz'


@memory_db
def test_new_happy_path(db):
    _, form, valid = setup_test(
        db, NewPolicyForm,
        '--name', 'baz',
        '--description', 'alpha bravo',
        '--disallowed-characters', 'abc123',
        '--disallowed-characters', 'xyz987',
        '--frequency', '42',
        '--generator', 'random',
        '--length', '7',
    )
    assert valid

    policy = form.create_policy()
    db.commit()
    db.refresh(policy)

    assert policy.description == 'alpha bravo'
    assert policy.disallowed_characters == '123789abcxyz'
    assert policy.frequency == 42
    assert policy.generator == 'random'
    assert policy.length == 7
    assert policy.name == 'baz'


@memory_db
def test_update_same_name(db):
    _, form, valid = setup_test(db, UpdatePolicyForm, '--new-name', 'foo')
    assert not valid
    assert len(form.new_name.errors) == 1
    msg = 'New name is the same as the current name'
    assert form.new_name.errors[0] == msg


@memory_db
def test_update_existing_name(db):
    _, form, valid = setup_test(db, UpdatePolicyForm, '--new-name', 'bar')
    assert not valid
    assert len(form.new_name.errors) == 1
    assert form.new_name.errors[0] == 'Policy with name "bar" already exists'


@memory_db
def test_update_empty(db):
    policy, form, valid = setup_test(db, UpdatePolicyForm)
    assert valid
    form.update_policy()
    db.commit()
    assert policy.description is None
    assert policy.disallowed_characters == 'abc'
    assert policy.frequency == Policy.DEFAULT_FREQUENCY
    assert policy.generator == Policy.DEFAULT_GENERATOR
    assert policy.length == Policy.DEFAULT_LENGTH
    assert policy.name == 'foo'


@memory_db
def test_update_happy_path(db):
    policy, form, valid = setup_test(
        db, UpdatePolicyForm,
        '--new-name', 'zulu',
        '--description', 'alpha bravo',
        '--allowed-characters', 'a1',
        '--allowed-characters', 'm',
        '--disallowed-characters', 'bc123',
        '--disallowed-characters', 'xyz987',
        '--frequency', '42',
        '--generator', 'random',
        '--length', '7',
    )
    assert valid

    form.update_policy()
    db.commit()


    assert policy.description == 'alpha bravo'
    assert policy.disallowed_characters == '123789bcxyz'
    assert policy.frequency == 42
    assert policy.generator == 'random'
    assert policy.length == 7
    assert policy.name == 'zulu'
