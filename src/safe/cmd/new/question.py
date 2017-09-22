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
from safe.compat import input
from safe.db import slug_error
from safe.ec import UNRECOGNIZED_ACCOUNT, VALIDATION_ERROR
from safe.model import Question


@new
def question():
    """Add a security and answer for an account."""
    parser.add_argument(
        'account-name',
        help='name/alias of account for which to add the security question',
        nargs=1,
    )
    parser.add_argument(
        'identifier',
        help='identifier for the new question (used when referencing it '
             'within safe) (identifier must not already exist for given '
             'account)',
        nargs=1,
    )
    parser.add_argument(
        '-a',
        '--answer',
        default=None,
        help='content of the answer (i.e. the answer itself) (if '
             'unspecified, safe will prompt for this value)',
    )
    parser.add_argument(
        '-q',
        '--question',
        default=None,
        help='content of the question (i.e. the question itself) (if '
             'unspecified, safe will prompt for this value)',
    )

    yield

    account_name = getattr(args, 'account-name')[0]
    account = account_for_slug(account_name)
    if account is None:
        yield UNRECOGNIZED_ACCOUNT

    identifier = args.identifier[0]
    msg = slug_error(identifier)
    if msg:
        print('error: identifier:', msg, file=sys.stderr)
        yield VALIDATION_ERROR

    if g.db.query(Question.id)\
           .filter((Question.account_id == account.id) &
                   (Question.identifier == identifier))\
           .count() > 0:
        fmt = 'error: identifer: there is already a question with ' \
              'identifier "%s" for account "%s"'
        print(fmt % (identifier, account.name), file=sys.stderr)
        yield VALIDATION_ERROR

    if args.question is None:
        args.question = input('Question: ')

    if args.answer is None:
        args.answer = input('Answer: ')

    g.db.add(Question(
        account_id=account.id,
        answer=args.answer,
        identifier=identifier,
        question=args.question,
    ))
    g.db.commit()
