# -*- coding: utf-8 -*-
"""
New account command.

:author: Joe Joyce <joe@decafjoe.com>
:copyright: Copyright (c) Joe Joyce and contributors, 2016-2017.
:license: BSD
"""
from __future__ import print_function

import sys

from clik import args, g, parser

from safe.cmd.new import new
from safe.ec import VALIDATION_ERROR
from safe.form.account import NewAccountForm


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

    # TODO(jjoyce): prompt for password if -p/--password was supplied

    g.commit_and_save()
