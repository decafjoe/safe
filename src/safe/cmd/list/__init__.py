# -*- coding: utf-8 -*-
"""
List command.

:author: Joe Joyce <joe@decafjoe.com>
:copyright: Copyright (c) Joe Joyce and contributors, 2016-2018.
:license: BSD
"""
from __future__ import print_function

import sys

import sqlalchemy
from clik import args, parser

from safe.app import safe
from safe.cmd.list.account import list_accounts
from safe.cmd.list.policy import list_policies
from safe.ec import NO_SUCH_ACCOUNT, NO_SUCH_POLICY
from safe.model import Account, Alias, Policy


@safe(name='list', alias='ls')
def list_():
    """List objects in the database."""
    parser.add_argument(
        'name',
        nargs='*',
        help='object name(s) to list',
    )
    parser.add_argument(
        '-p',
        '--policy',
        action='store_true',
        default=False,
        help='list policy object(s) instead of account(s)',
    )
    parser.add_argument(
        '-s',
        '--strict',
        action='store_true',
        default=False,
        help='match name/alias strictly',
    )
    parser.add_argument(
        '-v',
        '--verbose',
        action='count',
        default=0,
        dest='verbosity',
        help='list more detail (may be supplied multiple times)',
    )

    yield

    if args.policy:
        if Policy.query.count() == 0:
            print('no policies in the database')
            print('run "safe new policy -h" for help on creating policies')
            yield NO_SUCH_POLICY

        if args.strict and args.name:
            where = Policy.name.in_(args.name)
        else:
            clauses = [Policy.name.ilike('%%%s%%' % n) for n in args.name]
            where = sqlalchemy.or_(*clauses)

        policies = Policy.query.filter(where)
        if policies.count() < 1:
            print('error: no policy matches the query', file=sys.stderr)
            yield NO_SUCH_POLICY

        list_policies(policies, args.verbosity)
    else:
        if Account.query.count() == 0:
            print('no accounts in the database')
            print('run "safe new account -h" for help on creating accounts')
            yield NO_SUCH_ACCOUNT

        if args.strict and args.name:
            where = Account.name.in_(args.name) | Alias.value.in_(args.name)
        else:
            where = sqlalchemy.or_()
            for name in args.name:
                like = '%%%s%%' % name
                where |= Account.name.ilike(like) | Alias.value.ilike(like)

        accounts = Account.query.outerjoin(Alias).filter(where)
        if accounts.count() < 1:
            print('error: no account matches the query', file=sys.stderr)
            yield NO_SUCH_ACCOUNT

        list_accounts(accounts, args.verbosity)
