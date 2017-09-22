# -*- coding: utf-8 -*-
"""


:author: Joe Joyce <joe@decafjoe.com>
:copyright: Copyright (c) Joe Joyce and contributors, 2016-2017.
:license: BSD
"""
import sys

from clik import args, g, parser

from safe.cmd.new import new
from safe.cmd.util import account_for_slug
from safe.ec import UNRECOGNIZED_ACCOUNT, VALIDATION_ERROR
from safe.model import Code


@new
def code():
    """Add a new backup code for an account."""
    parser.add_argument(
        'account-name',
        help='name/alias of account for which to add the code',
        nargs=1,
    )
    parser.add_argument(
        'code',
        help='backup code',
        nargs=1,
    )

    yield

    account_name = getattr(args, 'account-name')[0]
    account = account_for_slug(account_name)
    if account is None:
        yield UNRECOGNIZED_ACCOUNT

    code = args.code[0]
    if Code.query\
           .filter((Code.account_id == account.id) & (Code.value == code))\
           .count() > 0:
        fmt = 'error: account "%s" already has code: %s'
        print(fmt % (account.name, code), file=sys.stderr)
        yield VALIDATION_ERROR

    g.db.add(Code(account_id=account.id, value=code))
    g.db.commit()
