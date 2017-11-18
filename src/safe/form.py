# -*- coding: utf-8 -*-
"""


:author: Joe Joyce <joe@decafjoe.com>
:copyright: Copyright (c) Joe Joyce and contributors, 2016-2017.
:license: BSD
"""
from wtforms import BooleanField, FieldList, Form, StringField
from wtforms.validators import Regexp, required, ValidationError

from clik import g

from safe.model import Account, Policy, SLUG_RE, SLUG_VALIDATION_ERROR_MESSAGE


slug_validator = Regexp(SLUG_RE, message=SLUG_VALIDATION_ERROR_MESSAGE)


def policy_validator(_, field):
    if field.data \
       and g.db.query(Policy.id).filter_by(name=field.data).count() < 1:
        raise ValidationError('No policy named "%s"' % field.data)


class AccountForm(Form):
    description = StringField('description')
    email = StringField('email')
    question_policy = StringField(
        'question_policy', validators=[policy_validator])
    password = BooleanField('password')
    password_policy = StringField(
        'password_policy', validators=[policy_validator])
    username = StringField('username')

    @staticmethod
    def configure_parser(parser):
        parser.add_argument(
            '-d',
            '--description',
            help='short description for the account (pass an empty string '
                 'to unset)',
        )
        parser.add_argument(
            '-e',
            '--email',
            help='email address associated with the account (pass an empty '
                 'string to unset)',
        )
        parser.add_argument(
            '-u',
            '--username',
            help='username associated with the account (pass an empty string '
                 'to unset)',
        )
        parser.add_argument(
            '-p',
            '--password',
            action='store_true',
            default=False,
            help='set password for account (do not pass a value, this will '
                 'prompt for the password)',
        )
        parser.add_argument(
            '--question-policy',
            help='name of the policy to apply to security question answers '
                 '(pass an empty string to unset)',
        )
        parser.add_argument(
            '--password-policy',
            help='name of the policy to apply to passwords (pass an empty '
                 'string to unset)',
        )


class NewAccountForm(AccountForm):
    aliases = FieldList(StringField('alias', validators=[slug_validator]))
    codes = FieldList(StringField('code'))
    name = StringField('name', validators=[required(), slug_validator])

    @classmethod
    def configure_parser(cls, parser):
        parser.add_argument(
            'name',
            help='name for the new account (must not already exist)',
            nargs=1,
        )
        super(NewAccountForm, cls).configure_parser(parser)
        parser.add_argument(
            '-a',
            '--alias',
            action='append',
            default=[],
            help='alias for this account (must not already exist) (may be '
                 'specified multiple times)',
        )
        parser.add_argument(
            '-c',
            '--code',
            action='append',
            default=[],
            help='backup code for this account (may be specified multiple '
                 'times)',
        )

    def validate(self):
        rv = super(NewAccountForm, self).validate()
        if not self.errors:
            exists_fmt = 'Account with name/alias "%s" already exists'
            if Account.id_for_slug(self.name.data):
                raise ValidationError(exists_fmt % self.name.data)
            checked_names = [self.name.data]
            for alias in self.aliases.data:
                if alias in checked_names:
                    fmt = 'Alias "%s" was already supplied'
                    raise ValidationError(fmt % alias)
                if Account.id_for_slug(alias):
                    raise ValidationError(exists_fmt % alias)
                checked_names.append(alias)
        return rv
