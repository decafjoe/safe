# -*- coding: utf-8 -*-
"""
Drop account command.

:author: Joe Joyce <joe@decafjoe.com>
:copyright: Copyright (c) Joe Joyce and contributors, 2016-2018.
:license: BSD
"""
from __future__ import print_function

import sys

from clik import args, g, parser

from safe.cmd.drop import drop
from safe.cmd.list.account import print_prolixly
from safe.ec import CANCELED, NO_SUCH_ACCOUNT
from safe.model import Account
from safe.util import prompt_bool


@drop(alias='a')
def account():
    """Drop an account from the database."""
    parser.add_argument(
        'name',
        nargs=1,
        help='name/alias of account to drop',
    )

    yield

    account = Account.for_slug(args.name[0])
    if account is None:
        print('error: no account named', args.name[0], file=sys.stderr)
        yield NO_SUCH_ACCOUNT

    print()
    print_prolixly(account)
    print()
    if not prompt_bool('Delete this account?', default=False):
        yield CANCELED

    g.db.delete(account)
    g.commit_and_save()
