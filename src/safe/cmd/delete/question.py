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
from safe.ec import CANCELED, UNRECOGNIZED_ACCOUNT, UNRECOGNIZED_QUESTION
from safe.model import Question
from safe.util import prompt_bool


@delete
def question():
    """Remove a security question from an account."""
    parser.add_argument(
        'account-name',
        help='name/alias of account from which to remove question',
        nargs=1,
    )
    parser.add_argument(
        'identifier',
        help='identifier of the question to remove',
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
    print('   account:', account.name)
    print('identifier:', question.identifier)
    print('  question:', question.question)
    print('    answer:', question.answer)
    print()
    if prompt_bool('Delete this question?', default=False):
        g.db.delete(question)
        g.db.commit()
    else:
        yield CANCELED
