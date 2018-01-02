# -*- coding: utf-8 -*-
"""
New account command.

:author: Joe Joyce <joe@decafjoe.com>
:copyright: Copyright (c) Joe Joyce and contributors, 2016-2018.
:license: BSD
"""
from __future__ import print_function

import getpass
import sys

from clik import args, g, parser

from safe.cmd.new import new
from safe.ec import VALIDATION_ERROR
from safe.form.account import NewAccountForm
from safe.model import Password


@new(alias='a')
def account():
    """Add an account to the database."""
    form = NewAccountForm()
    form.configure_parser(exclude=['name'])

    parser.add_argument(
        'name',
        nargs=1,
        help='name for the new account',
    )
    parser.add_argument(
        '-p',
        '--password',
        action='store_true',
        default=False,
        help='set the password for the new account (prompts for value)',
    )

    yield

    args.name = args.name[0]
    if not form.bind_and_validate():
        msg = 'error: there were validation error(s) with input value(s)'
        print(msg, file=sys.stderr)
        form.print_errors()
        yield VALIDATION_ERROR

    account = form.create_account()

    if args.password:
        while True:
            password = getpass.getpass('Password: ')
            confirm = getpass.getpass('Confirm: ')
            if password == confirm:
                break
            print('error: passwords did not match\n', file=sys.stderr)
        g.db.commit()
        g.db.add(Password(account_id=account.id, value=password))

    g.commit_and_save()
