# -*- coding: utf-8 -*-
"""
Data model for safe.

:author: Joe Joyce <joe@decafjoe.com>
:copyright: Copyright (c) Joe Joyce and contributors, 2016-2018.
:license: BSD
"""
import datetime
import re

from clik import g

from safe.db import ORM
from safe.sgen import generate


#: ORM wrapper instance.
#:
#: :type: :class:`safe.db.ORM`
orm = ORM()

#: Represents the ``cascade`` arguments necessary to effect deletion.
#:
#: :type: :class:`str`
CASCADE_DELETE = 'save-update, merge, delete'

#: Maximum length of a slug.
#:
#: :type: :class:`int`
SLUG_LENGTH = 20

#: Regular expression matching a valid slug.
#:
#: :type: :func:`re.compile`
SLUG_RE = re.compile(r'^[a-zA-Z0-9_/-]{1,%i}$' % SLUG_LENGTH)

#: User-level validation error message when a value does not match
#: :data:`SLUG_RE`.
#:
#: :type: :class:`str`
SLUG_VALIDATION_ERROR_MESSAGE = 'value must be 1-%i characters and contain ' \
                                'only letters, numbers, underscores, ' \
                                'forward slashes, and hyphens' % SLUG_LENGTH


def validate_slug(value):
    """
    Assert that ``value`` matches :data:`SLUG_RE`, return ``value`` if so.

    :param str value: Value to validate
    :raise: :exc:`AssertionError` if ``value`` does not match :data:`SLUG_RE`
    :return: Original value if valid
    :rtype: :class:`str`
    """
    assert SLUG_RE.search(value)
    return value


class Account(orm.Model):
    """Account model around which the whole application revolves."""

    __tablename__ = 'account'

    #: Primary key.
    #:
    #: :type: :class:`int`
    id = orm.Column(orm.Integer, primary_key=True)

    #: Query for :class:`Alias` instances.
    #:
    #: :type: :func:`sqlalchemy.orm.relationship` to :class:`Alias`
    alias_query = orm.relationship('Alias', lazy='dynamic')

    #: Eagerly loaded list of :class:`Alias` instances.
    #:
    #: :type: :class:`list` of :class:`Alias` instances
    aliases = orm.relationship('Alias', cascade=CASCADE_DELETE)

    #: Query for :class:`Code` instances.
    #:
    #: :type: :func:`sqlalchemy.orm.relationship` to :class:`Code`
    code_query = orm.relationship('Code', lazy='dynamic')

    #: Eagerly loaded list of :class:`Code` instances.
    #:
    #: :type: :class:`list` of :class:`Code` instances
    codes = orm.relationship('Code', cascade=CASCADE_DELETE)

    #: *(optional)* Short description for the account.
    #:
    #: :type: :class:`str` or ``None``
    description = orm.Column(orm.Text)

    #: *(optional)* Email associated with the account.
    #:
    #: :type: :class:`str` or ``None``
    email = orm.Column(orm.Text)

    #: Canonical name for the account.
    #:
    #: :type: :class:`str` matching :data:`SLUG_RE`
    name = orm.Column(orm.String(SLUG_LENGTH), nullable=False, unique=True)

    #: Query for :class:`Password` instances.
    #:
    #: :type: :func:`sqlalchemy.orm.relationship` to :class:`Password`
    password_query = orm.relationship('Password', lazy='dynamic')

    #: Eagerly loaded list of :class:`Password` instances.
    #:
    #: :type: :class:`list` of :class:`Password` instances
    passwords = orm.relationship('Password', cascade=CASCADE_DELETE)

    #: *(optional)* Foreign key of :class:`Policy` for passwords for
    #: this account.
    #:
    #: :type: :class:`int` or ``None``
    password_policy_id = orm.Column(orm.Integer, orm.ForeignKey('policy.id'))

    #: *(optional)* :class:`Policy` for passwords for this account.
    #:
    #: :type: :class:`Policy` or ``None``
    password_policy = orm.relationship(
        'Policy', foreign_keys=[password_policy_id])

    #: *(optional)* Foreign key of :class:`Policy` for security
    #: question answers for this account.
    #:
    #: :type: :class:`int` or ``None``
    question_policy_id = orm.Column(orm.Integer, orm.ForeignKey('policy.id'))

    #: *(optional)* :class:`Policy` for security question answers for
    #: this account.
    #:
    #: :type: :class:`Policy` or ``None``
    question_policy = orm.relationship(
        'Policy', foreign_keys=[question_policy_id])

    #: Query for :class:`Question` instances.
    #:
    #: :type: :func:`sqlalchemy.orm.relationship` to :class:`Question`
    question_query = orm.relationship('Question', lazy='dynamic')

    #: Eagerly loaded list of :class:`Question` instances.
    #:
    #: :type: :class:`list` of :class:`Question` instances
    questions = orm.relationship('Question', cascade=CASCADE_DELETE)

    #: *(optional)* Username associated with the account.
    #:
    #: :type: :class:`str` or ``None``
    username = orm.Column(orm.Text)

    @staticmethod
    def _filter_slug(query, slug):
        return query.outerjoin(Account.aliases)\
                    .filter((Account.name == slug) | (Alias.value == slug))

    @classmethod
    def id_for_slug(cls, slug):
        """
        Return ID for account with name or alias ``slug``.

        :return: ID if account exists for ``slug``, else ``None``
        :rtype: :class:`int` or ``None``
        """
        return cls._filter_slug(g.db.query(Account.id), slug).scalar()

    @classmethod
    def for_slug(cls, slug):
        """
        Return instance for account with name or alias ``slug``.

        :return: Account instance if account exists for ``slug``, else ``None``
        :rtype: :class:`Account` or ``None``
        """
        return cls._filter_slug(g.db.query(Account), slug).first()

    @orm.validates('name')
    def validate_name(self, _, name):
        """Validate that ``name`` matches :data:`SLUG_RE`."""
        return validate_slug(name)


class Alias(orm.Model):
    """Alias associated with an account."""

    __tablename__ = 'alias'

    #: Primary key.
    #:
    #: :type: :class:`int`
    id = orm.Column(orm.Integer, primary_key=True)

    #: Foreign key of :class:`Account` with which this alias is
    #: associated.
    #:
    #: :type: :class:`int`
    account_id = orm.Column(
        orm.Integer, orm.ForeignKey('account.id'), nullable=False)

    #: :class:`Account` instance with which this alias is associated.
    #:
    #: :type: :class:`Account`
    account = orm.relationship('Account')

    #: The alias.
    #:
    #: :type: :class:`str` matching :data:`SLUG_RE`
    value = orm.Column(orm.String(SLUG_LENGTH), nullable=False, unique=True)

    @orm.validates('value')
    def validate_value(self, _, value):
        """Validate that ``value`` matches :data:`SLUG_RE`."""
        return validate_slug(value)


class Code(orm.Model):
    """Backup code associated with an account."""

    __tablename__ = 'code'
    __table_args__ = (orm.UniqueConstraint(
        'account_id', 'value', name='_account_id_value_uc'),)

    #: Primary key.
    #:
    #: :type: :class:`int`
    id = orm.Column(orm.Integer, primary_key=True)

    #: Foreign key of :class:`Account` with which this code is
    #: associated.
    #:
    #: :type: :class:`int`
    account_id = orm.Column(
        orm.Integer, orm.ForeignKey('account.id'), nullable=False)

    #: :class:`Account` instance with which this code is associated.
    #:
    #: :type: :class:`Account`
    account = orm.relationship('Account')

    #: Indicates whether the code has been used.
    #:
    #: :type: :class:`str`
    used = orm.Column(orm.Boolean, default=False, nullable=False)

    #: The code.
    #:
    #: :type: :class:`str`
    value = orm.Column(orm.Text, nullable=False)


class Password(orm.Model):
    """Password associated with an account."""

    __tablename__ = 'password'

    #: Primary key.
    #:
    #: :type: :class:`int`
    id = orm.Column(orm.Integer, primary_key=True)

    #: Foreign key of :class:`Account` with which this password is
    #: associated.
    #:
    #: :type: :class:`int`
    account_id = orm.Column(
        orm.Integer, orm.ForeignKey('account.id'), nullable=False)

    #: :class:`Account` instance with which this password is
    #: associated.
    #:
    #: :type: :class:`Account`
    account = orm.relationship('Account')

    #: Datetime at which this password was set.
    #:
    #: :type: :class:`datetime.datetime`
    changed = orm.Column(
        orm.DateTime, default=datetime.datetime.today, nullable=False)

    #: The password.
    #:
    #: :type: :class:`str`
    value = orm.Column(orm.Text, nullable=False)


class Policy(orm.Model):
    """Policy specifying how secrets should be generated/rotated."""

    #: Default value for :attr:`frequency`.
    #:
    #: :type: :class:`int`
    DEFAULT_FREQUENCY = 0

    #: Default value for :attr:`generator`.
    #:
    #: :type: :class:`str`
    DEFAULT_GENERATOR = 'default'

    #: Default value for :attr:`length`.
    #:
    #: :type: :class:`int`
    DEFAULT_LENGTH = 24

    __tablename__ = 'policy'

    #: Primary key.
    #:
    #: :type: :class:`int`
    id = orm.Column(orm.Integer, primary_key=True)

    #: *(optional)* Short description for the policy.
    #:
    #: :type: :class:`str` or ``None``
    description = orm.Column(orm.Text)

    #: Characters that may not be used in generated secrets.
    #:
    #: :type: :class:`str`
    disallowed_characters = orm.Column(orm.Text, default='', nullable=False)

    #: Frequency (in days) at which secret should be rotated. 0 means
    #: never.
    #:
    #: :type: :class:`int`
    frequency = orm.Column(
        orm.Integer, default=DEFAULT_FREQUENCY, nullable=False)

    #: Name for the secret generator.
    #:
    #: :type: :class:`str` name of generator in :mod:`safe.generator`
    generator = orm.Column(
        orm.String(79), default=DEFAULT_GENERATOR, nullable=False)

    #: Length of generated secrets.
    #:
    #: :type: :class:`int`
    length = orm.Column(orm.Integer, default=DEFAULT_LENGTH, nullable=False)

    #: Name for the policy.
    #:
    #: :type: :class:`str` matching :data:`SLUG_RE`
    name = orm.Column(orm.String(SLUG_LENGTH), nullable=False, unique=True)

    @classmethod
    def id_for_name(cls, name):
        """
        Return ID for policy named ``name``.

        :return: ID if policy exists, else ``None``
        :rtype: :class:`int` or ``None``
        """
        return g.db.query(Policy.id).filter(Policy.name == name).scalar()

    @classmethod
    def for_name(cls, name):
        """
        Return instance for policy named ``name``.

        :return: Policy instance if policy exists, else ``None``
        :rtype: :class:`Policy` or ``None``
        """
        return g.db.query(Policy).filter(Policy.name == name).first()

    def generate_secret(self):
        """
        Return a secret meeting the parameters of this policy.

        :return: Randomly generated secret
        :rtype: :class:`str`
        """
        generator = generate[self.generator]
        return generator(self.length, self.disallowed_characters)

    @orm.validates('frequency')
    def validate_frequency(self, _, frequency):
        """Validate that ``frequency`` is zero or greater."""
        assert frequency > -1
        return frequency

    @orm.validates('generator')
    def validate_generator(self, _, generator):
        """Validate that ``generator`` is a valid generator name."""
        assert generator in generate
        return generator

    @orm.validates('length')
    def validate_length(self, _, length):
        """Validate that ``length`` is one or greater."""
        assert length > 0
        return length

    @orm.validates('name')
    def validate_name(self, _, name):
        """Validate that ``name`` matches :data:`SLUG_RE`."""
        return validate_slug(name)


class Question(orm.Model):
    """Security question and answer associated with an account."""

    __tablename__ = 'question'
    __table_args__ = (orm.UniqueConstraint(
        'account_id', 'identifier', name='_account_id_identifier_uc'),)

    #: Primary key.
    #:
    #: :type: :class:`int`
    id = orm.Column(orm.Integer, primary_key=True)

    #: Foreign key of :class:`Account` with which this security
    #: question is associated.
    #:
    #: :type: :class:`int`
    account_id = orm.Column(
        orm.Integer, orm.ForeignKey('account.id'), nullable=False)

    #: :class:`Account` instance with which this security question is
    #: associated.
    #:
    #: :type: :class:`Account`
    account = orm.relationship('Account')

    #: Answer to the security question.
    #:
    #: :type: :class:`str`
    answer = orm.Column(orm.Text, nullable=False)

    #: Short, human-friendly identifier for the question.
    #:
    #: :type: :class:`str` matching :data:`SLUG_RE`
    identifier = orm.Column(orm.String(SLUG_LENGTH), nullable=False)

    #: The security question.
    #:
    #: :type: :class:`str`
    question = orm.Column(orm.Text, nullable=False)

    @orm.validates('identifier')
    def validate_identifier(self, _, identifier):
        """Validate that ``identifier`` matches :data:`SLUG_RE`."""
        return validate_slug(identifier)
