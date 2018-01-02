# -*- coding: utf-8 -*-
"""
Secret generation for stored policies.

:author: Joe Joyce <joe@decafjoe.com>
:copyright: Copyright (c) Joe Joyce and contributors, 2016-2018.
:license: BSD
"""
from __future__ import print_function

import sys

from clik import args, parser

from safe.app import ignore_file_argument
from safe.cmd.gen import gen
from safe.ec import NO_SUCH_POLICY, VALIDATION_ERROR
from safe.model import Policy


DEFAULT_COUNT = 1


@gen(name='per-policy', alias='pp')
def per_policy():
    """Generate random strings to stdout using policy from database."""
    ignore_file_argument(False)

    parser.add_argument(
        'policy',
        help='name of policy',
        nargs=1,
    )
    parser.add_argument(
        '-c',
        '--count',
        default=DEFAULT_COUNT,
        help='number of secrets to generate (one per line) (default: '
             '%(default)s)',
        type=int,
    )

    yield

    if args.count < 1:
        print('error: -c/--count must be one or greater', file=sys.stderr)
        yield VALIDATION_ERROR

    policy = Policy.for_name(args.policy[0])
    if policy is None:
        print('error: no policy named', args.policy[0], file=sys.stderr)
        yield NO_SUCH_POLICY

    for _ in range(args.count):
        print(policy.generate_secret())
