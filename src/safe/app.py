# -*- coding: utf-8 -*-
"""
Root of the :mod:`clik` application.

:author: Joe Joyce <joe@decafjoe.com>
:copyright: Copyright (c) Joe Joyce and contributors, 2016-2018.
:license: BSD
"""
from __future__ import print_function

import getpass
import os
import sys

from clik import app, args, g, parser, run_children

from safe import __version__
from safe.db import open_database
from safe.ec import CANCELED, DECRYPTION_FAILED, FILE_ARGUMENT_REQUIRED, \
    MISSING_FILE, MISSING_GPG, SRM_FAILED
from safe.gpg import GPGError, GPGFile, PREFERRED_CIPHER
from safe.model import orm
from safe.srm import secure_delete, SecureDeleteError
from safe.util import expand_path, prompt_bool, temporary_directory


#: Argument name for the internal value that indicates whether the
#: file argument is required.
#:
#: :type: :class:`str`
IGNORE_FILE_ARGUMENT = '_safe_ignore_file_argument'


def ignore_file_argument(ignore=True):
    """
    Configure whether safe ignores the file argument for a command.

    Example::

        @safe
        def gen():
            # "Generate ad-hoc secret" command does not need a file
            ignore_file_argument()
            yield
            # Do stuff

        @gen
        def per_policy():
            # ...but gen's child command per-policy does need the file
            ignore_file_argument(False)
            yield
            # Do stuff

    """
    parser.set_defaults(**{IGNORE_FILE_ARGUMENT: ignore})


@app
def safe():
    """
    Password manager for people who like GPG and the command line.

    For more information, see the full project documentation at
    https://decafjoe-safe.readthedocs.io.
    """
    parser.add_argument(
        '--version',
        action='version',
        version='%%(prog)s %s' % __version__,
    )
    parser.add_argument(
        '-f',
        '--file',
        help='path to gpg-encrypted sqlite database',
    )
    parser.add_argument(
        '-c',
        '--cipher',
        default=PREFERRED_CIPHER,
        help='cipher to use for encryption (default: %(default)s)',
        metavar='CIPHER',
    )

    yield

    if getattr(args, IGNORE_FILE_ARGUMENT, False):
        yield run_children()

    if args.file is None:
        msg = 'error: -f/--file argument is required with this command'
        print(msg, file=sys.stderr)
        yield FILE_ARGUMENT_REQUIRED

    path = expand_path(args.file)
    if not os.path.exists(path):
        print('error: database file does not exist:', path, file=sys.stderr)
        yield MISSING_FILE

    def print_error(message, stdout, stderr, path_=None):
        if path_ is None:
            path_ = path
        print('error: %s: %s' % (message, path_), file=sys.stderr)
        if stdout:
            print('\nstdout:\n%s' % stdout, file=sys.stderr)
        if stderr:
            print('\nstderr:\n%s' % stderr, file=sys.stderr)

    try:
        gpg_file = GPGFile(path)
    except GPGError as e:
        print_error(e.message, e.stdout, e.stderr)
        yield MISSING_GPG

    password = None
    if gpg_file.symmetric:
        password = getpass.getpass()

    try:
        with temporary_directory() as tmp:
            plaintext_path = os.path.join(tmp, 'db')

            while True:
                try:
                    gpg_file.decrypt_to(plaintext_path, password)
                    break
                except GPGError as e:
                    print_error(e.message, e.stdout, e.stderr)
                    print(file=sys.stderr)
                    prompt = 'Command failed. Try again?'
                    if prompt_bool(prompt, default=False):
                        print('\n\n', file=sys.stderr)
                        if gpg_file.symmetric:
                            password = getpass.getpass()
                    else:
                        yield DECRYPTION_FAILED

            try:
                g.db = open_database(plaintext_path)
                cipher = args.cipher

                def commit_and_save():
                    """
                    Commit outstanding db changes and save encrypted file.

                    :raise: :exc:`safe.gpg.GPGError` if encryption fails
                    """
                    g.db.commit()
                    gpg_file.save(plaintext_path, cipher=cipher)

                g.commit_and_save = commit_and_save
                with orm.bind(g.db):
                    ec = run_children()
                    if ec:
                        yield ec
            finally:
                try:
                    secure_delete(plaintext_path)
                except SecureDeleteError as e:
                    print_error(e.message, e.stdout, e.stderr)
                    yield SRM_FAILED
    except KeyboardInterrupt:
        print('canceled by user', file=sys.stderr)
        yield CANCELED
