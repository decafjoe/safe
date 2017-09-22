# -*- coding: utf-8 -*-
"""


:author: Joe Joyce <joe@decafjoe.com>
:copyright: Copyright (c) Joe Joyce and contributors, 2016-2017.
:license: BSD
"""
import sys

from clik import args, g, parser

from safe.cmd.update import update
from safe.cmd.util import PolicyForm
from safe.ec import UNRECOGNIZED_POLICY, VALIDATION_ERROR
from safe.model import Policy


@update
def policy():
    """Update settings for a policy."""
    parser.add_argument(
        'name',
        help='name of the policy to update',
        nargs=1,
    )
    parser.add_argument(
        '-n',
        '--new-name',
        default=None,
        help='new name for the policy (must not already exist)',
    )

    PolicyForm.configure_parser(parser)

    yield

    name = args.name[0]
    policy = Policy.query.filter_by(name=name).first()
    if policy is None:
        print('error: no policy with name:', name, file=sys.stderr)
        yield UNRECOGNIZED_POLICY

    form = PolicyForm(args)
    if form.errors:
        form.print_validation_errors()
        yield VALIDATION_ERROR

    if args.description is not None:
        policy.description = args.description or None
    if args.disallowed_chars is not None:
        policy.disallowed_characters = form.disallowed_chars
    if args.frequency is not None:
        policy.frequency = args.frequency
    if args.length is not None:
        policy.length = args.length
    if args.new_name is not None:
        policy.name = args.new_name

    g.db.add(policy)
    g.db.commit()
