# -*- coding: utf-8 -*-
"""


:author: Joe Joyce <joe@decafjoe.com>
:copyright: Copyright (c) Joe Joyce and contributors, 2016-2017.
:license: BSD
"""
import os
import sys

import sqlalchemy
from clik import args, parser
from clik_shell import exclude_from_shell

from safe.app import allow_missing_file, safe
from safe.ec import ENCRYPTION_FAILED, FILE_EXISTS
#from safe.gpg import GPG
from safe.model import orm
from safe.util import expand_path, temporary_directory


@exclude_from_shell
@safe
def init():
    """Create and initialize the database."""
    allow_missing_file()

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

    path = expand_path(args.file)
    if os.path.exists(path):
        print('error: database file already exists:', path, file=sys.stderr)
        yield FILE_EXISTS

    with temporary_directory() as tmp:
        tmp_path = os.path.join(tmp, 'safe')

        engine = sqlalchemy.create_engine('sqlite:///%s' % tmp_path)
        metadata = orm.Model.metadata
        metadata.create_all(bind=engine, tables=metadata.tables.values())

        command = (
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

        process = GPG(command)
        process.wait()
        if process.returncode:
            yield ENCRYPTION_FAILED
