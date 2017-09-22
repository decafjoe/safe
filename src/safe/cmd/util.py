# -*- coding: utf-8 -*-
"""


:author: Joe Joyce <joe@decafjoe.com>
:copyright: Copyright (c) Joe Joyce and contributors, 2016-2017.
:license: BSD
"""
from __future__ import print_function

import sys

from clik import g

from safe.db import slug_error
from safe.model import Account, Alias, Policy
from safe.util import prompt_bool


def filter_by_account_slug(query, slug):
    where = (Account.name == slug) | (Alias.value == slug)
    return query.outerjoin(Account.aliases).filter(where)


def account_id_for_slug(slug, print_error=True):
    rv = filter_by_account_slug(g.db.query(Account.id), slug).scalar()
    if rv is None and print_error is True:
        print('error: no account with name/alias:', slug, file=sys.stderr)
    return rv


def account_for_slug(slug, print_error=True):
    rv = filter_by_account_slug(Account.query, slug).first()
    if rv is None and print_error is True:
        print('error: no account with name/alias:', slug, file=sys.stderr)
    return rv


class Form(object):
    def __init__(self, args):
        self.args = args
        self.errors = []

    def print_validation_errors(self):
        if self.errors:
            print('error: validation errors (see below)', file=sys.stderr)
            fmt = 'error: %s (value: "%s"): %s'
            for key, value, msg in self.errors:
                print(fmt % (key, value, msg), file=sys.stderr)


class AccountForm(Form):
    @staticmethod
    def configure_parser(parser):
        parser.add_argument(
            '-d',
            '--description',
            default=None,
            help='short description for the account',
        )
        parser.add_argument(
            '-e',
            '--email',
            default=None,
            help='email address with which account is associated',
            metavar='EMAIL',
        )
        parser.add_argument(
            '-u',
            '--username',
            default=None,
            help='username with which account is associated',
            metavar='USERNAME',
        )
        parser.add_argument(
            '-p',
            '--password-policy',
            default=None,
            help='policy to apply to password for this account',
            metavar='POLICY_NAME',
        )
        parser.add_argument(
            '-q',
            '--question-policy',
            default=None,
            help='policy to apply to security questions/answers for this '
            'account',
            metavar='POLICY_NAME',
        )

    def __init__(self, args):
        super(AccountForm, self).__init__(args)

        name = args.name[0]
        msg = slug_error(name)
        if msg:
            self.errors.append(('name', name, msg))

        new_name = getattr(args, 'new_name', None)
        if new_name:
            msg = slug_error(new_name)
            if msg:
                self.errors.append(('new-name', new_name, msg))
            else:
                if new_name == name:
                    msg = 'new name is same as existing name'
                    self.errors.append(('new-name', new_name, msg))
                else:
                    if account_id_for_slug(new_name, print_error=False):
                        msg = 'already an account with that name/alias'
                        self.errors.append(('new-name', new_name, msg))

        if args.email and '@' not in args.email:
            msg = 'missing @ sign in email address'
            self.errors.append(('email', args.email, msg))

        for key in ('password', 'question'):
            value = getattr(args, '%s_policy' % key)
            if value:
                policy_id = g.db.query(Policy.id)\
                                .filter(Policy.name == value)\
                                .scalar()
                if policy_id is None:
                    msg = 'no policy with that name'
                    self.errors.append(('%s-policy' % key, value, msg))
                setattr(self, '%s_policy_id' % key, policy_id)

    def check_references(self):
        email = self.args.email
        if email \
           and Account.query.filter(Account.email == email).count() < 1:
            fmt = 'Email address "%s" is not in the database. Is it correct?'
            if not prompt_bool(fmt % email, default=True):
                return False

        username = self.args.username
        if username \
           and Account.query.filter(Account.username == username).count() < 1:
            fmt = 'Username "%s" is not in the database. Is it correct?'
            if not prompt_bool(fmt % username, default=True):
                return False

        return True


class PolicyForm(Form):
    @staticmethod
    def configure_parser(parser, defaults=False):
        parser.add_argument(
            '-d',
            '--description',
            default=None,
            help='short description of the policy',
        )

        frequency_default = None
        frequency_help = 'frequency with which to rotate value (0 means ' \
                         'never rotate) '
        if defaults:
            frequency_default = Policy.DEFAULT_FREQUENCY
            frequency_help += ' (default: %(default)i)'
        parser.add_argument(
            '-f',
            '--frequency',
            default=frequency_default,
            help=frequency_help,
            type=int,
        )

        length_default = None
        length_help = 'length of generated values'
        if defaults:
            length_default = Policy.DEFAULT_LENGTH
            length_help += ' (default: %(default)i)'
        parser.add_argument(
            '-l',
            '--length',
            default=length_default,
            help=length_help,
            type=int,
        )

        parser.add_argument(
            '-c',
            '--disallowed-chars',
            action='append',
            default=None,
            help='characters to disallow in generated values (arguments may '
                 'contain sequences of characters) (this argument may be '
            'specified multiple times',
        )

    def __init__(self, args):
        super(PolicyForm, self).__init__(args)

        name = args.name[0]
        msg = slug_error(name)
        if msg:
            self.errors.append(('name', name, msg))

        new_name = getattr(args, 'new_name', None)
        if new_name:
            msg = slug_error(new_name)
            if msg:
                self.errors.append(('new-name', new_name, msg))
            else:
                if new_name == name:
                    msg = 'new name is same as existing name'
                    self.errors.append(('new-name', new_name, msg))
                else:
                    if g.db.query(Policy.id)\
                           .filter(Policy.name == new_name)\
                           .count() > 0:
                        msg = 'already a policy with that name'
                        self.errors.append(('new-name', new_name, msg))

        if args.frequency < 0:
            msg = 'frequency must be >= 0'
            self.errors.append(('frequency', args.frequency, msg))

        if args.length < 1:
            self.errors.append(('length', args.length, 'length must be >= 1'))

        self.disallowed_chars = None
        if args.disallowed_chars is not None:
            disallowed_chars = set()
            for characters in args.disallowed_chars:
                for character in characters:
                    disallowed_chars.add(character)
            self.disallowed_chars = sorted(disallowed_chars)
