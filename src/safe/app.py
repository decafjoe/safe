# -*- coding: utf-8 -*-
"""
Root of the :mod:`clik` application.

:author: Joe Joyce <joe@decafjoe.com>
:copyright: Copyright (c) Joe Joyce and contributors, 2016-2017.
:license: BSD
"""
import getpass
import os
import re
import shutil
import sys

import sqlalchemy
import sqlalchemy.orm
from clik import app, args, g, parser, run_children

from safe.ec import CANCELED, DECRYPTION_FAILED, ENCRYPTION_FAILED, \
    MISSING_FILE, MISSING_GPG, SRM_FAILED, UNRECOGNIZED_FILE
from safe.gpg import GPGError, GPGFile, PREFERRED_CIPHER
from safe.model import orm
from safe.srm import SRM, SRM_EXECUTABLE
from safe.util import expand_path, prompt_bool, temporary_directory


ALLOW_MISSING_FILE = '_safe_allow_missing_file'


def allow_missing_file():
    parser.set_defaults(**{ALLOW_MISSING_FILE: True})


@app
def safe():
    """
    A password manager for people who like GPG and the command line.

    For more information, see the full project documentation at
    https://decafjoe-safe.readthedocs.io.
    """
    parser.add_argument(
        '-f',
        '--file',
        help='path to gpg-encrypted sqlite database',
        required=True,
    )
    parser.add_argument(
        '-c',
        '--cipher',
        default=PREFERRED_CIPHER,
        help='cipher to use for encryption (default: %(default)s)',
        metavar='CIPHER',
    )

    yield

    if SRM_EXECUTABLE is None:
        msg = 'warning: running without a secure file removal program'
        print(msg, file=sys.stderr)

    path = expand_path(args.file)
    if not os.path.exists(path):
        if getattr(args, ALLOW_MISSING_FILE, False):
            yield run_children()
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
                uri = 'sqlite:///%s' % plaintext_path
                engine = sqlalchemy.create_engine(uri)
                g.db = sqlalchemy.orm.sessionmaker(bind=engine)()
                with orm.bind(g.db):
                    ec = run_children()
                    if ec:
                        yield ec
                    try:
                        gpg_file.save(plaintext_path, cipher=args.cipher)
                    except GPGError as e:
                        print_error(e.message, e.stdout, e.stderr)
                        yield ENCRYPTION_FAILED
            finally:
                if SRM_EXECUTABLE is not None:
                    process = SRM(plaintext_path)
                    stdout, stderr = process.communicate()
                    if process.returncode:
                        msg = 'failed to securely remove plaintext file'
                        print_error(msg, stdout, stderr, plaintext_path)
                        yield SRM_FAILED
    except KeyboardInterrupt:
        print('canceled by user', file=sys.stderr)
        yield CANCELED
