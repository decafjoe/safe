# -*- coding: utf-8 -*-
"""
New policy command.

:author: Joe Joyce <joe@decafjoe.com>
:copyright: Copyright (c) Joe Joyce and contributors, 2016-2018.
:license: BSD
"""
from __future__ import print_function

import sys

from clik import args, g, parser

from safe.cmd.new import new
from safe.ec import VALIDATION_ERROR
from safe.form.policy import NewPolicyForm


@new(alias='p')
def policy():
    """Add a policy to the database."""
    form = NewPolicyForm()
    form.configure_parser(exclude=['name'])

    parser.add_argument(
        'name',
        nargs=1,
        help='name for the new policy',
    )

    yield

    args.name = args.name[0]
    if not form.bind_and_validate():
        msg = 'error: there were validation error(s) with input value(s)'
        print(msg, file=sys.stderr)
        form.print_errors()
        yield VALIDATION_ERROR
    form.create_policy()
    g.commit_and_save()
