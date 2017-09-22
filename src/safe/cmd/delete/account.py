# -*- coding: utf-8 -*-
"""


:author: Joe Joyce <joe@decafjoe.com>
:copyright: Copyright (c) Joe Joyce and contributors, 2016-2017.
:license: BSD
"""
from clik import args, g, parser

from safe.cmd.delete import delete
from safe.cmd.util import account_for_slug
from safe.ec import CANCELED, UNRECOGNIZED_ACCOUNT
from safe.util import prompt_bool


@delete
def account():
    """Delete an account an associated objects from the database."""
    parser.add_argument(
        'name',
        help='name/alias of account to delete',
        nargs=1,
    )

    yield

    account_name = args.name[0]
    account = account_for_slug(account_name)
    if account is None:
        yield UNRECOGNIZED_ACCOUNT

    # TODO(jjoyce): print out a pretty, detailed list of objects that
    #               will be deleted -- easy way to allow user to
    #               visually double-check that they're deleting the
    #               right account

    print()
    if prompt_bool('Delete account "%s"?' % account.name, default=False) \
       and prompt_bool('Are you sure?', default=False):
        g.db.delete(account)
        g.db.commit()
    else:
        yield CANCELED
