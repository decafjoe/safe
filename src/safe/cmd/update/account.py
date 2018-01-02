# -*- coding: utf-8 -*-
"""
Update account command.

:author: Joe Joyce <joe@decafjoe.com>
:copyright: Copyright (c) Joe Joyce and contributors, 2016-2018.
:license: BSD
"""
from __future__ import print_function

import getpass
import sys

from clik import args, g, parser

from safe.cmd.update import update
from safe.compat import input
from safe.ec import NO_SUCH_ACCOUNT, VALIDATION_ERROR
from safe.form.account import Operation, UpdateAccountForm
from safe.model import Account, Password


@update(alias='a')
def account():
    """Update an account and/or its associated data."""
    parser.add_argument(
        'account',
        help='name or alias of account to update',
        nargs=1,
    )
    parser.add_argument(
        '-p',
        '--password',
        action='store_true',
        default=False,
        help='set the password for an account (prompts for value)',
    )

    form = UpdateAccountForm()
    form.configure_parser()

    yield

    account = Account.for_slug(args.account[0])
    if account is None:
        print('error: no account with name/alias:', args.account)
        yield NO_SUCH_ACCOUNT

    if not form.bind_and_validate(account):
        msg = 'error: there were validation error(s) with input value(s)'
        print(msg, file=sys.stderr)
        form.print_errors()
        yield VALIDATION_ERROR

    new, update = {}, {}
    operations = form.question.operations
    for i, (op, subject, details) in enumerate(operations):
        if op == Operation.Q and not details:
            update.setdefault(subject.identifier, [subject, None, None])
            update[subject.identifier][1] = i
        elif op == Operation.A and not details:
            update.setdefault(subject.identifier, [subject, None, None])
            update[subject.identifier][2] = i
        elif op == Operation.NEW:
            new[subject] = i

    for identifier in sorted(new):
        print('\nAdding new security question with identifier', identifier)
        operations[new[identifier]][2] = input('Question: '), input('Answer: ')

    for identifier in sorted(update):
        print('\nUpdating security question with identifier', identifier)
        question, question_i, answer_i = update[identifier]
        for label, attr in (('Question', 'question'), ('Answer', 'answer')):
            value = getattr(question, attr)
            if not value:
                value = '<empty>'
            print('%s: %s' % (label, value))
        if question_i is not None:
            operations[question_i][2] = input('New question: ')
        if answer_i is not None:
            operations[answer_i][2] = input('New answer: ')

    if args.password:
        print('\nUpdating password for account')
        while True:
            password = getpass.getpass('New password: ')
            confirm = getpass.getpass('Confirm: ')
            if password == confirm:
                break
            print('error: passwords did not match\n', file=sys.stderr)
        g.db.add(Password(account_id=account.id, value=password))

    form.update_account()
    g.commit_and_save()
