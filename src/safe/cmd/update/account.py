# -*- coding: utf-8 -*-
"""


:author: Joe Joyce <joe@decafjoe.com>
:copyright: Copyright (c) Joe Joyce and contributors, 2016-2017.
:license: BSD
"""
from clik import args, g, parser

from safe.cmd.update import update
from safe.cmd.util import account_for_slug, AccountForm
from safe.ec import CANCELED, UNRECOGNIZED_ACCOUNT, VALIDATION_ERROR


@update
def account():
    """Update settings for an account."""
    parser.add_argument(
        'name',
        help='name/alias of the account to update',
        nargs=1,
    )
    parser.add_argument(
        '-n',
        '--new-name',
        default=None,
        help='new name for the account (must not already exist)',
    )

    AccountForm.configure_parser(parser)

    yield

    name = args.name[0]
    account = account_for_slug(name)
    if account is None:
        yield UNRECOGNIZED_ACCOUNT

    form = AccountForm(args)
    if form.errors:
        form.print_validation_errors()
        yield VALIDATION_ERROR
    if not form.check_references():
        yield CANCELED

    if args.description is not None:
        account.description = args.description or None
    if args.email is not None:
        account.email = args.email or None
    if args.new_name is not None:
        account.name = args.new_name
    if args.password_policy is not None:
        account.password_policy_id = form.password_policy_id
    if args.question_policy is not None:
        account.question_policy_id = form.question_policy_id
    if args.username is not None:
        account.username = args.username or None

    g.db.add(account)
    g.db.commit()
