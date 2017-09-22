# -*- coding: utf-8 -*-
"""


:author: Joe Joyce <joe@decafjoe.com>
:copyright: Copyright (c) Joe Joyce and contributors, 2016-2017.
:license: BSD
"""
import getpass
import sys

from clik import args, g, parser

from safe.cmd.set import set_
from safe.cmd.util import account_for_slug
from safe.ec import UNRECOGNIZED_ACCOUNT
from safe.model import Password


@set_
def password():
    """Set the password for an account."""
    parser.add_argument(
        'name',
        help='name/alias of account for which to set answer',
        nargs=1,
    )

    yield

    name = args.name[0]
    account = account_for_slug(name)
    if account is None:
        yield UNRECOGNIZED_ACCOUNT

    while True:
        password = getpass.getpass('New password: ')
        confirm = getpass.getpass('Confirm: ')
        if password == confirm:
            break
        print('error: passwords did not match\n', file=sys.stderr)

    g.db.add(Password(account_id=account.id, value=password))
    g.db.commit()
