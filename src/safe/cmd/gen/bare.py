# -*- coding: utf-8 -*-
"""
Ad-hoc secret generation command.

:author: Joe Joyce <joe@decafjoe.com>
:copyright: Copyright (c) Joe Joyce and contributors, 2016-2018.
:license: BSD
"""
from __future__ import print_function

import sys

from clik import args, parser

from safe.app import ignore_file_argument
from safe.cmd.gen import gen
from safe.ec import VALIDATION_ERROR
from safe.sgen import generate


DEFAULT_COUNT = 1
DEFAULT_LENGTH = 32


@gen.bare
def gen_ad_hoc():
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
        print('error: -c/--count must be one or greater', file=sys.stderr)
        yield VALIDATION_ERROR

    if args.length < 1:
        print('error: -l/--length must be one or greater', file=sys.stderr)
        yield VALIDATION_ERROR

    for _ in range(args.count):
        print(generate[args.generator](args.length))
