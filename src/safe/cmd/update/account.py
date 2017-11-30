# -*- coding: utf-8 -*-
"""
Update account command.

:author: Joe Joyce <joe@decafjoe.com>
:copyright: Copyright (c) Joe Joyce and contributors, 2016-2017.
:license: BSD
"""
from __future__ import print_function

import sys

from clik import args, parser

from safe.cmd.update import update
from safe.ec import UNRECOGNIZED_ACCOUNT, VALIDATION_ERROR
from safe.form.account import UpdateAccountForm
from safe.model import Account


@update
def account():
    """Update an account and/or its associated data."""
    parser.add_argument(
        'account',
        help='name or alias of account to update',
        nargs=1,
    )
    parser.add_argument(
        '-p',
        '--password',
        action='store_true',
        default=False,
        help='set the password for an account (prompts for value)',
    )

    form = UpdateAccountForm()
    form.configure_parser()

    yield

    account = Account.for_slug(args.account[0])
    if account is None:
        print('error: no account with name/alias:', args.account)
        yield UNRECOGNIZED_ACCOUNT

    if not form.bind_and_validate(account):
        msg = 'error: there were validation error(s) with input value(s)'
        print(msg, file=sys.stderr)
        form.print_errors()
        yield VALIDATION_ERROR

    # TODO(jjoyce): prompt for password if -p/--password was supplied
    # TODO(jjoyce): look at question operations and prompt for new and
    #               updated values

    form.update_account()
    g.commit_and_save()
