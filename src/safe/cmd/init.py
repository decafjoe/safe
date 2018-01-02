# -*- coding: utf-8 -*-
"""
Database initialization command.

:author: Joe Joyce <joe@decafjoe.com>
:copyright: Copyright (c) Joe Joyce and contributors, 2016-2018.
:license: BSD
"""
from __future__ import print_function

import os
import subprocess
import sys

import sqlalchemy
from clik import args, parser
from clik_shell import exclude_from_shell

from safe.app import ignore_file_argument, safe
from safe.ec import ENCRYPTION_FAILED, FILE_EXISTS
from safe.gpg import get_gpg_executable
from safe.model import orm
from safe.util import expand_path, temporary_directory


@exclude_from_shell
@safe
def init():
    """Create and initialize the database."""
    ignore_file_argument()

    parser.add_argument(
        'file',
        help='database file',
        nargs=1,
    )

    mode_group = parser.add_mutually_exclusive_group(required=True)
    mode_group.add_argument(
        '-k',
        '--key',
        default=None,
        help='use key-based (asymmetric) encryption (specify the public key '
             'id to encrypt to as the value for this argument)',
        metavar='KEYID',
    )
    mode_group.add_argument(
        '-p',
        '--password',
        action='store_true',
        default=False,
        help='use password-based (symmetric) encryption',
    )

    yield

    path = expand_path(args.file[0])
    if os.path.exists(path):
        print('error: database file already exists:', path, file=sys.stderr)
        yield FILE_EXISTS

    with temporary_directory() as tmp:
        tmp_path = os.path.join(tmp, 'db')

        engine = sqlalchemy.create_engine('sqlite:///%s' % tmp_path)
        metadata = orm.Model.metadata
        metadata.create_all(bind=engine, tables=metadata.tables.values())

        command = (
            get_gpg_executable(),
            '--armor',
            '--cipher-algo', args.cipher,
            '--output', path,
            '--quiet',
        )
        if args.password:
            command += ('--symmetric',)
        else:
            command += ('--recipient', args.key, '--encrypt')
        command += (tmp_path,)

        process = subprocess.Popen(command)
        process.wait()
        if process.returncode:
            yield ENCRYPTION_FAILED
