# -*- coding: utf-8 -*-
"""


:author: Joe Joyce <joe@decafjoe.com>
:copyright: Copyright (c) Joe Joyce and contributors, 2016-2017.
:license: BSD
"""
from clik import args, g, parser

from safe.cmd.new import new
from safe.cmd.util import PolicyForm
from safe.ec import VALIDATION_ERROR
from safe.model import Policy


@new
def policy():
    """Create a new policy for passwords / security questions."""
    parser.add_argument(
        'name',
        help='name of new policy (used when referencing it within safe) '
             '(must not already exist)',
        nargs=1,
    )
    PolicyForm.configure_parser(parser, defaults=True)

    yield

    name = args.name[0]
    form = PolicyForm(args)
    if not form.errors \
       and g.db.query(Policy.id).filter(Policy.name == name).count() > 0:
        form.errors.append(('name', name, 'already a policy with that name'))
    if form.errors:
        form.print_validation_errors()
        yield VALIDATION_ERROR

    g.db.add(Policy(
        description=args.description,
        disallowed_characters=form.disallowed_chars,
        frequency=args.frequency,
        length=args.length,
        name=name,
    ))
    g.db.commit()
