# -*- coding: utf-8 -*-
"""


:author: Joe Joyce <joe@decafjoe.com>
:copyright: Copyright (c) Joe Joyce and contributors, 2016-2017.
:license: BSD
"""
import sys

from clik import args, g, parser

from safe.cmd.set import set_
from safe.cmd.util import account_for_slug
from safe.ec import UNRECOGNIZED_ACCOUNT, UNRECOGNIZED_QUESTION
from safe.model import Question


@set_
def question():
    """Set the security question for an account."""
    parser.add_argument(
        'account-name',
        help='name/alias of account for which to set answer',
        nargs=1,
    )
    parser.add_argument(
        'identifier',
        help='identifier of the question to set',
        nargs=1,
    )

    yield

    account_name = getattr(args, 'account-name')[0]
    account = account_for_slug(account_name)
    if account is None:
        yield UNRECOGNIZED_ACCOUNT

    identifier = args.identifier[0]
    filter_kwargs = dict(account_id=account.id, identifier=identifier)
    question = Question.query.filter_by(**filter_kwargs).first()
    if question is None:
        fmt = 'error: identifier: no question with identifier "%s" for ' \
              'account "%s"'
        print(fmt % (identifier, account.name), file=sys.stderr)
        yield UNRECOGNIZED_QUESTION

    print()
    print('Current question:', question.question)
    question.question = input('New question: ')
    g.db.add(question)
    g.db.commit()
