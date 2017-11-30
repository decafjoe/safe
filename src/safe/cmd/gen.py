# -*- coding: utf-8 -*-
"""
Secret generation utility command.

:author: Joe Joyce <joe@decafjoe.com>
:copyright: Copyright (c) Joe Joyce and contributors, 2016-2017.
:license: BSD
"""
from __future__ import print_function

import sys

from clik import args, parser

from safe.app import ignore_file_argument, safe
from safe.ec import INVALID_ARGUMENT
from safe.sgen import generate


DEFAULT_COUNT = 1
DEFAULT_LENGTH = 32


@safe
def gen():
    """Generate and print random strings to stdout."""
    ignore_file_argument()

    generator_choices = sorted(generate)
    generator_help = 'generator to use (choices: %s) (default: ' \
                     '%%(default)s)' % ', '.join(generator_choices)
    parser.add_argument(
        '-g',
        '--generator',
        choices=generator_choices,
        default='default',
        help=generator_help,
        metavar='GENERATOR',
    )
    parser.add_argument(
        '-l',
        '--length',
        default=DEFAULT_LENGTH,
        help='length of secret to generate (default: %(default)s)',
        type=int,
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
        print('error: -c/--count must be 1 or greater', file=sys.stderr)
        yield INVALID_ARGUMENT

    if args.length < 1:
        print('error: -l/--length must be 1 or greater', file=sys.stderr)
        yield INVALID_ARGUMENT

    for _ in range(args.count):
        print(generate[args.generator](args.length))
