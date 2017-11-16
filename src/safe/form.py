# -*- coding: utf-8 -*-
"""


:author: Joe Joyce <joe@decafjoe.com>
:copyright: Copyright (c) Joe Joyce and contributors, 2016-2017.
:license: BSD
"""
from wtforms import BooleanField, FieldList, Form, StringField
from wtforms.validators import Email, Regexp

from safe.db import SLUG_RE


slug_message = 'value must be 1-20 characters and contain only letters, ' \
               'numbers, underscores, forward slashes, and hyphens'
slug_validator = Regexp(SLUG_RE, message=slug_message)


class AccountForm(wtforms.Form):
    description = StringField('description')
    email = StringField('email', validators=[
        Email(message='invalid email address'),
    ])
    password = BooleanField('password')
    username = StringField('username')

    @staticmethod
    def configure_parser(parser):
        parser.add_argument(
            '-d',
            '--description',
            help='short description for the account',
        )
        parser.add_argument(
            '-e',
            '--email',
            help='email address associated with the account',
        )
        parser.add_argument(
            '-u',
            '--username',
            help='username associated with the account',
        )
        parser.add_argument(
            '-p',
            '--password',
            action='store_true',
            default=False,
            help='set password for account (do not pass a value, this will '
                 'prompt for the password)',
        )


class NewAccountForm(AccountForm):
    aliases = FieldList(StringField('alias', validators=[slug_validator]))
    codes = FieldList(StringField('code'))
    name = StringField('name', validators=[slug_validator])

    @classmethod
    def configure_parser(cls, parser):
        parser.add_argument(
            'name',
            help='name for the new account (must not already exist)',
            nargs=1,
        )
        super(NewAccountForm, cls).configure_parser(parser)
