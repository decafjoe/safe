# -*- coding: utf-8 -*-
"""
Drop policy command.

:author: Joe Joyce <joe@decafjoe.com>
:copyright: Copyright (c) Joe Joyce and contributors, 2016-2018.
:license: BSD
"""
from __future__ import print_function

import sys

from clik import args, g, parser

from safe.cmd.drop import drop
from safe.ec import CANCELED, NO_SUCH_POLICY
from safe.model import Account, Policy
from safe.util import prompt_bool


@drop(alias='p')
def policy():
    """Drop a policy from the database."""
    parser.add_argument(
        'name',
        nargs=1,
        help='name of policy to drop',
    )

    yield

    policy = Policy.for_name(args.name[0])
    if policy is None:
        print('error: no policy named', args.name[0], file=sys.stderr)
        yield NO_SUCH_POLICY

    accounts = {}
    related = (('password', 'passwords'), ('question', 'security questions'))
    for attr, description in related:
        query = Account.query\
                       .filter_by(**{'%s_policy_id' % attr: policy.id})\
                       .all()
        for account in query:
            if account.name in accounts:
                accounts[account.name] += ', %s' % description
            else:
                accounts[account.name] = description

    if len(accounts) > 0:
        print()
        fmt = 'The policy "%s" is associated with the following accounts.'
        print(fmt % policy.name)
        msg = 'The accounts will be disassociated with the policy before it ' \
              'is deleted, but will otherwise remain intact.'
        print(msg)
        fmt = '- %s (%s)'
        for name in sorted(accounts):
            print(fmt % (name, accounts[name]))
        print()

    msg = 'Delete policy "%s"?' % policy.name
    if not prompt_bool(msg, default=False):
        yield CANCELED

    g.db.delete(policy)
    g.commit_and_save()
