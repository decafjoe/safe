# -*- coding: utf-8 -*-
"""
Tests for :class:`safe.form.NewAccountForm`.

:author: Joe Joyce <joe@decafjoe.com>
:copyright: Copyright (c) Joe Joyce and contributors, 2016-2017.
:license: BSD
"""
import pytest
from clik.argparse import ArgumentParser

from safe.form import NewAccountForm
from safe.model import Account, Alias, Code, Policy, Question

from test import memory_db  # noqa: I100


def setup_test(db, *argv):
    db.add(Account(name='foo'))
    db.add(Policy(name='alpha'))
    db.add(Policy(name='bravo'))
    db.commit()

    parser = ArgumentParser()
    form = NewAccountForm()
    form.configure_parser(parser)
    valid = form.bind_and_validate(args=parser.parse_args(argv))

    return form, valid


@memory_db
def test_policy_validator(db):
    form, valid = setup_test(db, '--name', 'foo', '--password-policy', 'golf')
    assert not valid
    assert len(form.password_policy.errors) == 1
    assert form.password_policy.errors[0] == 'No policy with that name'


@pytest.mark.parametrize('value', ['not valid', 'bad:punct', '', 'a' * 30])
def test_slug_validator(value):
    @memory_db
    def inner(db):
        _, valid = setup_test(db, '--name', value)
        assert not valid
    inner()


@memory_db
def test_name_exists(db):
    form, valid = setup_test(db, '--name', 'foo')
    assert not valid
    assert len(form.name.errors) == 1
    assert form.name.errors[0] == 'Account with that name/alias already exists'


@memory_db
def test_alias_already_supplied_as_name(db):
    form, valid = setup_test(db, '--name', 'bar', '--alias', 'bar')
    assert not valid
    assert len(form.alias.errors) == 1
    msg = 'Alias "bar" already supplied as name or other alias'
    assert form.alias.errors[0] == msg


@memory_db
def test_alias_already_supplied_as_alias(db):
    form, valid = setup_test(
        db,
        '--name', 'bar',
        '--alias', 'baz',
        '--alias', 'baz',
    )
    assert not valid
    assert len(form.alias.errors) == 1
    msg = 'Alias "baz" already supplied as name or other alias'
    assert form.alias.errors[0] == msg


@memory_db
def test_alias_exists(db):
    form, valid = setup_test(db, '--name', 'bar', '--alias', 'foo')
    assert not valid
    assert len(form.alias.errors) == 1
    msg = 'Account with name/alias "foo" already exists'
    assert form.alias.errors[0] == msg


@memory_db
def test_empty(db):
    form, valid = setup_test(db, '--name', 'bar')
    assert valid
    account = form.create_account()
    db.add(account)
    db.commit()
    assert account.description is None
    assert account.email is None
    assert account.name == 'bar'
    assert account.question_policy_id is None
    assert account.password_policy_id is None
    assert account.username is None
    assert Alias.query.count() == 0
    assert Code.query.count() == 0
    assert Question.query.count() == 0


@memory_db
def test_happy_path(db):
    form, valid = setup_test(
        db,
        '--name', 'bar',
        '--description', 'charlie delta',
        '--email', 'me@example.com',
        '--question-policy', 'alpha',
        '--password-policy', 'bravo',
        '--username', 'my_username',
        '--alias', 'echo',
        '--alias', 'foxtrot',
        '--code', 'golf',
        '--code', 'hotel',
    )
    assert valid

    account = form.create_account()
    db.add(account)
    db.commit()
    db.refresh(account)

    alpha = Policy.query.filter_by(name='alpha').first()
    assert alpha
    bravo = Policy.query.filter_by(name='bravo').first()
    assert bravo

    assert account.description == 'charlie delta'
    assert account.email == 'me@example.com'
    assert account.name == 'bar'
    assert account.question_policy_id == alpha.id
    assert account.password_policy_id == bravo.id
    assert account.username == 'my_username'

    assert Alias.query.count() == 2
    echo = Alias.query.filter_by(value='echo').first()
    assert echo
    assert echo.account_id == account.id
    foxtrot = Alias.query.filter_by(value='foxtrot').first()
    assert foxtrot
    assert foxtrot.account_id == account.id

    assert Code.query.count() == 2
    golf = Code.query.filter_by(value='golf').first()
    assert golf
    assert golf.account_id == account.id
    hotel = Code.query.filter_by(value='hotel').first()
    assert hotel
    assert hotel.account_id == account.id

    assert Question.query.count() == 0
