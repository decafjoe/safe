# -*- coding: utf-8 -*-
"""


:author: Joe Joyce <joe@decafjoe.com>
:copyright: Copyright (c) Joe Joyce and contributors, 2016-2017.
:license: BSD
"""
import sys

from clik import args, g, parser

from safe.cmd.new import new
from safe.cmd.util import account_id_for_slug
from safe.db import slug_error
from safe.ec import UNRECOGNIZED_ACCOUNT, VALIDATION_ERROR
from safe.model import Alias


@new
def alias():
    """Add an alias for an account."""
    parser.add_argument(
        'account-name',
        help='name/alias of account for which to add the alias',
        nargs=1,
    )
    parser.add_argument(
        'alias',
        help='alias',
        nargs=1,
    )

    yield

    account_name = getattr(args, 'account-name')[0]
    account_id = account_id_for_slug(account_name)
    if account_id is None:
        yield UNRECOGNIZED_ACCOUNT

    alias = args.alias[0]
    msg = slug_error(alias)
    if msg:
        print('error: alias:', msg, file=sys.stderr)
        yield VALIDATION_ERROR

    if account_id_for_slug(alias, print_error=False) is not None:
        fmt = 'error: alias: there is already an account/alias with name "%s"'
        print(fmt % alias, file=sys.stderr)
        yield VALIDATION_ERROR

    g.db.add(Alias(account_id=account_id, value=alias))
    g.db.commit()
