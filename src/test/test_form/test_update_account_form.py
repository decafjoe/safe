# -*- coding: utf-8 -*-
"""
Tests for :class:`safe.form.account.UpdateAccountForm`.

:author: Joe Joyce <joe@decafjoe.com>
:copyright: Copyright (c) Joe Joyce and contributors, 2016-2017.
:license: BSD
"""
import pytest
from clik.argparse import ArgumentParser

from safe.form.account import UpdateAccountForm
from safe.model import Account, Alias, Code, Policy, Question

from test import memory_db  # noqa: I100


def setup_test(db, *argv):
    account = Account(name='foo')
    db.add(account)
    db.commit()
    db.refresh(account)
    db.add(Alias(account_id=account.id, value='bar'))
    db.add(Code(account_id=account.id, value='abc123'))
    db.add(Code(account_id=account.id, value='xyz987'))
    db.add(Question(
        account_id=account.id,
        identifier='foxtrot',
        question='golf?',
        answer='hotel',
    ))
    db.add(Question(
        account_id=account.id,
        identifier='baz',
        question='qux?',
        answer='quux',
    ))
    db.add(Policy(name='alpha'))
    db.add(Policy(name='bravo'))
    db.commit()
    db.expire_all()

    parser = ArgumentParser()
    form = UpdateAccountForm()
    form.configure_parser(parser)
    valid = form.bind_and_validate(account, args=parser.parse_args(argv))

    return account, form, valid


def error_cases_for_field(field_name, *cases):
    params = []
    for case in cases:
        params.append((case[1:], case[0]))

    @pytest.mark.parametrize('argv,message', params)
    def test(argv, message):
        @memory_db
        def inner(db):
            fmt = '--%s=%%s' % field_name.replace('_', '-')
            _, form, valid = setup_test(db, *[fmt % arg for arg in argv])
            assert not valid
            field = getattr(form, field_name)
            assert len(field.errors) == 1
            assert field.errors[0] == message
        inner()
    return test


test_alias = error_cases_for_field(
    'alias',
    ('Unknown operation "asdf"', 'asdf:foo'),
    ('Account with name/alias "foo" already exists', 'foo'),
    ('Alias "garply" already scheduled for addition', 'garply', 'garply'),
    ('No alias named "garply" associated with account', 'rm:garply'),
    ('Alias "bar" already scheduled for removal', 'rm:bar', 'rm:bar'),
)

test_code = error_cases_for_field(
    'code',
    ('Unknown operation "asdf"', 'asdf:abc123'),
    ('Code "abc123" is already associated with this account', 'abc123'),
    ('No code "def456" associated with account', 'rm:def456'),
    ('Code "def456" already scheduled for addition', 'def456', 'def456'),
    ('Code "abc123" already scheduled for removal', 'rm:abc123', 'rm:abc123'),
    (
        'Code "abc123" already scheduled for removal',
        'rm:abc123', 'used:abc123',
    ),
    (
        'Code "abc123" already scheduled to be marked used',
        'used:abc123', 'used:abc123',
    ),
    (
        'Code "abc123" already scheduled to be marked used',
        'used:abc123', 'rm:abc123',
    ),
)

test_new_name = error_cases_for_field(
    'new_name',
    ('Account with name/alias "bar" already exists', 'bar'),
    ('New name is the same as the current name', 'foo'),
)

test_question = error_cases_for_field(
    'question',
    ('No operation specified', ''),
    ('Unknown operation "asdf"', 'asdf:garply'),
    (
        'Question with identifier "baz" is already associated with this '
        'account',
        'new:baz',
    ),
    (
        'Question with identifier "garply" already scheduled for addition',
        'new:garply', 'new:garply',
    ),
    (
        'No question with identifier "garply" associated with account',
        'rm:garply',
    ),
    (
        'No question with identifier "garply" associated with account',
        'q:garply',
    ),
    (
        'No question with identifier "garply" associated with account',
        'a:garply',
    ),
    (
        'Question with identifier "baz" already scheduled for removal',
        'rm:baz', 'rm:baz',
    ),
    (
        'Question with identifier "baz" already scheduled for removal',
        'rm:baz', 'q:baz',
    ),
    (
        'Question with identifier "baz" already scheduled for removal',
        'rm:baz', 'a:baz',
    ),
    (
        'Question with identifier "baz" already scheduled to be updated',
        'q:baz', 'rm:baz',
    ),
    (
        'Question with identifier "baz" already scheduled to be updated',
        'a:baz', 'rm:baz',
    ),
    (
        'Redundant "q" operation for question with identifier "baz"',
        'q:baz', 'q:baz',
    ),
    (
        'Redundant "a" operation for question with identifier "baz"',
        'a:baz', 'a:baz',
    ),
)


@memory_db
def test_empty(db):
    account, form, valid = setup_test(db)
    assert valid

    form.update_account()
    db.commit()
    db.expire_all()

    assert account.description is None
    assert account.email is None
    assert account.question_policy_id is None
    assert account.password_policy_id is None
    assert account.username is None

    assert Alias.query.count() == 1
    bar = Alias.query.all()[0]
    assert bar.account_id == account.id
    assert bar.value == 'bar'

    assert account.name == 'foo'

    assert Code.query.count() == 2
    abc = Code.query.filter_by(value='abc123').first()
    assert abc
    assert abc.account_id == account.id
    assert not abc.used
    xyz = Code.query.filter_by(value='xyz987').first()
    assert xyz
    assert xyz.account_id == account.id
    assert not xyz.used

    assert Question.query.count() == 2
    baz = Question.query.filter_by(identifier='baz').first()
    assert baz.account_id == account.id
    assert baz.question == 'qux?'
    assert baz.answer == 'quux'
    foxtrot = Question.query.filter_by(identifier='foxtrot').first()
    assert foxtrot.account_id == account.id
    assert foxtrot.question == 'golf?'
    assert foxtrot.answer == 'hotel'


@memory_db
def test_happy_path(db):
    account, form, valid = setup_test(
        db,
        '--description', 'this is a description',
        '--email', 'me@example.com',
        '--question-policy', 'alpha',
        '--password-policy', 'bravo',
        '--username', 'my_username',
        '--alias', 'charlie',
        '--alias', 'rm:bar',
        '--code', 'delta',
        '--code', 'rm:abc123',
        '--code', 'used:xyz987',
        '--new-name', 'echo',
        '--question', 'rm:baz',
        '--question', 'new:india',
        '--question', 'q:foxtrot:juliet?',
        '--question', 'a:foxtrot:kilo',
    )
    assert valid

    form.update_account()
    db.commit()
    db.expire_all()

    alpha = Policy.query.filter_by(name='alpha').first()
    assert alpha
    bravo = Policy.query.filter_by(name='bravo').first()
    assert bravo

    assert account.description == 'this is a description'
    assert account.email == 'me@example.com'
    assert account.question_policy_id == alpha.id
    assert account.password_policy_id == bravo.id
    assert account.username == 'my_username'

    assert Alias.query.count() == 1
    alias = Alias.query.all()[0]
    assert alias.account_id == account.id
    assert alias.value == 'charlie'

    assert account.name == 'echo'

    assert Code.query.count() == 2
    xyz = Code.query.filter_by(value='xyz987').first()
    assert xyz
    assert xyz.account_id == account.id
    assert xyz.used
    delta = Code.query.filter_by(value='delta').first()
    assert delta
    assert delta.account_id == account.id
    assert not delta.used

    assert Question.query.count() == 2
    foxtrot = Question.query.filter_by(identifier='foxtrot').first()
    assert foxtrot.account_id == account.id
    assert foxtrot.question == 'juliet?'
    assert foxtrot.answer == 'kilo'
    india = Question.query.filter_by(identifier='india').first()
    assert india.account_id == account.id
    assert india.question == ''
    assert india.answer == ''


@memory_db
def test_empty_q_and_a(db):
    account, form, valid = setup_test(
        db,
        '--question', 'q:baz',
        '--question', 'a:baz',
    )
    assert valid

    form.update_account()
    db.commit()
    db.expire_all()

    assert Question.query.count() == 2
    baz = Question.query.filter_by(identifier='baz').first()
    assert baz
    assert baz.question == ''
    assert baz.answer == ''


@memory_db
def test_new_question_with_details(db):
    account, form, valid = setup_test(db, '--question', 'new:zulu')
    assert valid

    assert len(form.question.operations) == 1
    assert form.question.operations[0] == ['new', 'zulu', None]
    form.question.operations[0][2] = ('yankee?', 'xray')
    form.update_account()
    db.commit()
    db.expire_all()

    assert Question.query.count() == 3
    zulu = Question.query.filter_by(identifier='zulu').first()
    assert zulu
    assert zulu.question == 'yankee?'
    assert zulu.answer == 'xray'


@memory_db
def test_remove_question_with_other_unrelated_operations(db):
    account, form, valid = setup_test(
        db,
        '--question', 'new:zulu',
        '--question', 'rm:baz',
    )
    assert valid
