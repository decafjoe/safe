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
from safe.gpg import GPG, GPG_EXECUTABLE, GPG_EXECUTABLE_NAME, PREFERRED_CIPHER
from safe.model import orm
from safe.srm import SRM, SRM_EXECUTABLE
from safe.util import expand_path, prompt_bool, temporary_directory


ALLOW_MISSING_FILE = '_safe_allow_missing_file'
KEYID_RE = re.compile(r'keyid (?P<keyid>[0-9A-F]+)')


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

    if GPG_EXECUTABLE is None:
        msg = 'error: could not find gpg executable:'
        print(msg, GPG_EXECUTABLE_NAME, file=sys.stderr)
        yield MISSING_GPG

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
        with temporary_directory() as tmp:
            plaintext_path = os.path.join(tmp, 'db')
            encrypted_path = '%s.gpg' % plaintext_path

            command = (
                '--batch',
                '--homedir', tmp,
                '--passphrase', '',
                '--quiet',
                '--list-packets',
                path,
            )
            process = GPG(command, capture=True)
            stdout, stderr = process.communicate()

            symmetric = None
            for line in stdout.splitlines():
                if line.startswith(':symkey'):
                    symmetric = True
                    password = getpass.getpass()
                    break
                elif line.startswith(':pubkey'):
                    symmetric = False
                    password = None
                    match = KEYID_RE.search(line)
                    if not match:
                        msg = 'could not find keyid in pubkey packet'
                        print_error(msg, line, stderr)
                        yield UNRECOGNIZED_FILE
                    keyid = match.groupdict()['keyid']
                    break
            if symmetric is None:
                msg = 'no :symkey or :pubkey packets to indicate file type'
                print_error(msg, stdout, stderr)
                yield UNRECOGNIZED_FILE

            command = (
                '--batch',
                '--output', plaintext_path,
                '--quiet',
            )
            if symmetric:
                command += ('--passphrase-fd', '0')
            command += ('--decrypt', path)

            while True:
                process = GPG(command, capture=True)
                stdout, stderr = process.communicate(password)
                if not process.returncode:
                    break

                print_error('failed to decrypt file', stdout, stderr)
                print(file=sys.stderr)
                if prompt_bool('Command failed. Try again?', default=False):
                    print('\n\n', file=sys.stderr)
                    if symmetric:
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
                    command = (
                        '--armor',
                        '--batch',
                        '--cipher-algo', args.cipher,
                        '--output', encrypted_path,
                        '--quiet',
                    )
                    if symmetric:
                        command += ('--passphrase-fd', '0', '--symmetric')
                    else:
                        command += ('--recipient', keyid, '--encrypt')
                    command += (plaintext_path,)
                    process = GPG(command)
                    stdout, stderr = process.communicate(password)
                    if process.returncode:
                        msg = 'failed to re-encrypt file'
                        print_error(msg, stdout, stderr)
                        yield ENCRYPTION_FAILED
                    shutil.move(encrypted_path, path)
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
