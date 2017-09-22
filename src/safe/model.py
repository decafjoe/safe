# -*- coding: utf-8 -*-
"""


:author: Joe Joyce <joe@decafjoe.com>
:copyright: Copyright (c) Joe Joyce and contributors, 2016-2017.
:license: BSD
"""
import datetime

from safe.db import ORM


orm = ORM()
CASCADE_DELETE = 'save-update, merge, delete'


class Account(orm.Model):
    __tablename__ = 'account'
    id = orm.Column(orm.Integer, primary_key=True)
    alias_query = orm.relationship('Alias', lazy='dynamic')
    aliases = orm.relationship('Alias', cascade=CASCADE_DELETE)
    code_query = orm.relationship('Code', lazy='dynamic')
    codes = orm.relationship('Code', cascade=CASCADE_DELETE)
    description = orm.Column(orm.Text)
    email = orm.Column(orm.Text)
    name = orm.Column(orm.Slug, nullable=False, unique=True)
    password_query = orm.relationship('Password', lazy='dynamic')
    passwords = orm.relationship('Password', cascade=CASCADE_DELETE)
    password_policy_id = orm.Column(orm.Integer, orm.ForeignKey('policy.id'))
    password_policy = orm.relationship(
        'Policy', foreign_keys=[password_policy_id])
    question_policy_id = orm.Column(orm.Integer, orm.ForeignKey('policy.id'))
    question_policy = orm.relationship(
        'Policy', foreign_keys=[question_policy_id])
    question_query = orm.relationship('Question', lazy='dynamic')
    questions = orm.relationship('Question', cascade=CASCADE_DELETE)
    username = orm.Column(orm.Text)

    @property
    def password(self):
        return self.password_query.order_by(Password.changed.desc()).first()


class Alias(orm.Model):
    __tablename__ = 'alias'
    id = orm.Column(orm.Integer, primary_key=True)
    account_id = orm.Column(
        orm.Integer, orm.ForeignKey('account.id'), nullable=False)
    account = orm.relationship('Account')
    value = orm.Column(orm.Slug, nullable=False, unique=True)


class Code(orm.Model):
    __tablename__ = 'code'
    __table_args__ = (orm.UniqueConstraint(
        'account_id', 'value', name='_account_id_value_uc'),)
    id = orm.Column(orm.Integer, primary_key=True)
    account_id = orm.Column(
        orm.Integer, orm.ForeignKey('account.id'), nullable=False)
    account = orm.relationship('Account')
    value = orm.Column(orm.Text, nullable=False)


class Password(orm.Model):
    __tablename__ = 'password'
    id = orm.Column(orm.Integer, primary_key=True)
    account_id = orm.Column(
        orm.Integer, orm.ForeignKey('account.id'), nullable=False)
    account = orm.relationship('Account')
    changed = orm.Column(
        orm.DateTime, default=datetime.datetime.today, nullable=False)
    value = orm.Column(orm.Text, nullable=False)


class Policy(orm.Model):
    DEFAULT_FREQUENCY = 0
    DEFAULT_LENGTH = 24

    __tablename__ = 'policy'
    id = orm.Column(orm.Integer, primary_key=True)
    description = orm.Column(orm.Text)
    disallowed_characters = orm.Column(orm.Text, default='', nullable=False)
    frequency = orm.Column(
        orm.Integer, default=DEFAULT_FREQUENCY, nullable=False)
    length = orm.Column(orm.Integer, default=DEFAULT_LENGTH, nullable=False)
    name = orm.Column(orm.Slug, nullable=False, unique=True)


class Question(orm.Model):
    __tablename__ = 'question'
    __table_args__ = (orm.UniqueConstraint(
        'account_id', 'identifier', name='_account_id_identifier_uc'),)
    id = orm.Column(orm.Integer, primary_key=True)
    account_id = orm.Column(
        orm.Integer, orm.ForeignKey('account.id'), nullable=False)
    account = orm.relationship('Account')
    answer = orm.Column(orm.Text, nullable=False)
    identifier = orm.Column(orm.Slug, nullable=False)
    question = orm.Column(orm.Text, nullable=False)
