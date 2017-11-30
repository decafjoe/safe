# -*- coding: utf-8 -*-
"""
Drop policy command.

:author: Joe Joyce <joe@decafjoe.com>
:copyright: Copyright (c) Joe Joyce and contributors, 2016-2017.
:license: BSD
"""
from __future__ import print_function

import sys

from clik import args, g, parser

from safe.cmd.drop import drop
from safe.ec import VALIDATION_ERROR
from safe.model import Policy


@drop(alias='p')
def policy():
    """Drop a policy from the database."""
    parser.add_argument(
        'name',
        nargs=1,
        help='name of policy to drop',
    )

    yield

    policy = Policy.for_name(args.name[0])
    if policy is None:
        print('error: no policy named', args.name[0], file=sys.stderr)
        yield VALIDATION_ERROR

    # TODO(jjoyce): confirm deletion
    #               print list of associated accounts?

    g.db.delete(policy)
    g.commit_and_save()
