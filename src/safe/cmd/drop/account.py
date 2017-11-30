# -*- coding: utf-8 -*-
"""
Drop account command.

:author: Joe Joyce <joe@decafjoe.com>
:copyright: Copyright (c) Joe Joyce and contributors, 2016-2017.
:license: BSD
"""
from __future__ import print_function

import sys

from clik import args, g, parser

from safe.cmd.drop import drop
from safe.ec import VALIDATION_ERROR
from safe.model import Account


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
        yield VALIDATION_ERROR

    # TODO(jjoyce): confirm deletion
    #               print list of objects that will also be dropped?
    #                 aliases, codes, questions, etc

    g.db.delete(account)
    g.commit_and_save()
