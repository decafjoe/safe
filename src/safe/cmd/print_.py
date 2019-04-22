# -*- coding: utf-8 -*-
"""
Print to stdout command.

:author: Joe Joyce <joe@decafjoe.com>
:copyright: Copyright (c) Joe Joyce and contributors, 2016-2019.
:license: BSD
"""
from __future__ import print_function

import sys

from clik import args, parser

from safe.app import safe
from safe.ec import NO_SUCH_ACCOUNT, NO_SUCH_QUESTION, PASSWORD_NOT_SET
from safe.model import Account, Password


@safe(name='print')
def print_():
    """Print secret to stdout."""
    parser.add_argument(
        'name',
        nargs=1,
        help='name of the account for which to print secret',
    )
    parser.add_argument(
        '-q',
        '--question',
        help='print answer to security question with given identifier to '
             'clipboard instead of the account password',
    )

    yield

    account = Account.for_slug(args.name[0])
    if account is None:
        print('error: no account named', args.name[0], file=sys.stderr)
        yield NO_SUCH_ACCOUNT

    if args.question:
        question = account.question_query\
                          .filter_by(identifier=args.question)\
                          .first()
        if question is None:
            fmt = 'error: no question with identifier "%s" associated with ' \
                  'account "%s"'
            print(fmt % (args.question, account.name), file=sys.stderr)
            yield NO_SUCH_QUESTION
        value = question.answer
    else:
        password = account.password_query\
                          .order_by(Password.changed.desc())\
                          .limit(1)\
                          .first()
        if password is None:
            msg = 'error: no password set for account "%s"' % account.name
            print(msg, file=sys.stderr)
            yield PASSWORD_NOT_SET
        value = password.value

    print(value)
