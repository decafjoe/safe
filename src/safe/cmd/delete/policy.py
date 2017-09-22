# -*- coding: utf-8 -*-
"""


:author: Joe Joyce <joe@decafjoe.com>
:copyright: Copyright (c) Joe Joyce and contributors, 2016-2017.
:license: BSD
"""
import sys

from clik import args, g, parser

from safe.cmd.delete import delete
from safe.ec import CANCELED, UNRECOGNIZED_POLICY
from safe.model import Account, Policy
from safe.util import prompt_bool


@delete
def policy():
    """Delete a policy from the database."""
    parser.add_argument(
        'name',
        help='',
        nargs=1,
    )

    yield

    name = args.name[0]
    policy = Policy.query.filter_by(name=name).first()
    if policy is None:
        print('error: name: no policy with name:', name, file=sys.stderr)
        yield UNRECOGNIZED_POLICY

    names_query = g.db.query(Account.name)\
                      .filter((Account.password_policy_id == policy.id) |
                              (Account.question_policy_id == policy.id))\
                      .order_by(Account.name)
    account_names = [row[0] for row in names_query]

    print()
    print('            name:', policy.name)
    print('     description:', policy.description or '<not set>')
    print('          length:', policy.length)
    print('       frequency:', policy.frequency)
    print('disallowed chars:', policy.disallowed_characters or '<none>')
    print()
    if len(account_names) > 0:
        print('RELATED ACCOUNTS\n  - %s' % '\n  - '.join(account_names))
        print()
    if prompt_bool('Delete this policy?', default=False):
        # TODO(jjoyce): can we do this with a cascade?
        where = (Account.password_policy_id == policy.id) | \
                (Account.question_policy_id == policy.id)
        for account in Account.query.filter(where):
            if account.password_policy_id == policy.id:
                account.password_policy_id = None
                g.db.add(account)
            if account.question_policy_id == policy.id:
                account.question_policy_id = None
                g.db.add(account)
        g.db.delete(policy)
        g.db.commit()
    else:
        yield CANCELED
