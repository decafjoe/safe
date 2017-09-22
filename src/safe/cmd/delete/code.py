# -*- coding: utf-8 -*-
"""


:author: Joe Joyce <joe@decafjoe.com>
:copyright: Copyright (c) Joe Joyce and contributors, 2016-2017.
:license: BSD
"""
import sys

from clik import args, g, parser

from safe.cmd.delete import delete
from safe.cmd.util import account_for_slug
from safe.ec import CANCELED, UNRECOGNIZED_ACCOUNT, UNRECOGNIZED_CODE
from safe.model import Code
from safe.util import prompt_bool


@delete
def code():
    """Remove a backup code from an account."""
    parser.add_argument(
        'account-name',
        help='name/alias of account from which to remove code',
        nargs=1,
    )
    parser.add_argument(
        'code',
        help='code to remove',
        nargs=1,
    )

    yield

    account_name = getattr(args, 'account-name')[0]
    account = account_for_slug(account_name)
    if account is None:
        yield UNRECOGNIZED_ACCOUNT

    code_value = args.code[0]
    filter_kwargs = dict(account_id=account.id, value=code_value)
    code = Code.query.filter_by(**filter_kwargs).first()
    if code is None:
        fmt = 'error: code: no code "%s" for account "%s"'
        print(fmt % (code_value, account.name), file=sys.stderr)
        yield UNRECOGNIZED_CODE

    print()
    print('account:', account.name)
    print('   code:', code_value)
    print()
    if prompt_bool('Delete this code?', default=False):
        g.db.delete(code)
        g.db.commit()
    else:
        yield CANCELED
