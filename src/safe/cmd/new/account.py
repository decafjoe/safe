# -*- coding: utf-8 -*-
"""


:author: Joe Joyce <joe@decafjoe.com>
:copyright: Copyright (c) Joe Joyce and contributors, 2016-2017.
:license: BSD
"""
from clik import args, g, parser

from safe.cmd.new import new
from safe.cmd.util import account_id_for_slug, AccountForm
from safe.ec import CANCELED, VALIDATION_ERROR
from safe.model import Account


@new
def account():
    """Add an account to the database."""
    parser.add_argument(
        'name',
        help='name of new account (used when referencing it within safe) '
             '(must not already exist)',
        nargs=1,
    )

    AccountForm.configure_parser(parser)

    yield

    name = args.name[0]
    form = AccountForm(args)
    if not form.errors and account_id_for_slug(name, print_error=False):
        msg = 'already an account with that name/alias'
        form.errors.append(('name', name, msg))
    if form.errors:
        form.print_validation_errors()
        yield VALIDATION_ERROR
    if not form.check_references():
        yield CANCELED

    account = Account(
        description=args.description,
        email=args.email,
        name=name,
        username=args.username,
    )
    if args.password_policy:
        account.password_policy_id = form.password_policy_id
    if args.question_policy:
        account.question_policy_id = form.question_policy_id

    g.db.add(account)
    g.db.commit()
