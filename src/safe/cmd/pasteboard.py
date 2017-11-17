# -*- coding: utf-8 -*-
"""


:author: Joe Joyce <joe@decafjoe.com>
:copyright: Copyright (c) Joe Joyce and contributors, 2016-2017.
:license: BSD
"""
from __future__ import print_function

import subprocess
import sys
import time

from clik import args, g, parser

from safe.app import safe
from safe.cmd.util import account_for_slug
from safe.ec import PASTEBOARD_COPY_FAILED, UNRECOGNIZED_ACCOUNT, \
    UNSET_PASSWORD, UNSUPPORTED_PASTEBOARD
from safe.util import get_executable


COPY_TIME = 5
PBCOPY_EXECUTABLE = get_executable('pbcopy')
XCLIP_EXECUTABLE = get_executable('xclip')


def pboard(value):
    cmd = (PBCOPY_EXECUTABLE, '-pboard', 'general')
    process = subprocess.Popen(cmd, stdin=subprocess.PIPE)
    process.communicate(value.encode('utf-8'))
    return process.returncode


def xclip(value):
    cmd = (XCLIP_EXECUTABLE, '-selection', 'clipboard')
    process = subprocess.Popen(cmd, stdin=subprocess.PIPE)
    process.communicate(data)
    process.wait()
    time.sleep(0.1)
    return process.returncode



@safe(alias='pb')
def pasteboard():
    """Copy a password to the pasteboard temporarily."""
    parser.add_argument(
        'name',
        help='name/alias of account for which to add the alias',
        nargs=1,
    )

    yield

    if PBCOPY_EXECUTABLE is None:
        if XCLIP_EXECUTABLE is None:
            msg = 'error: no suitable clipboard commands found ' \
                  '(pbcopy/pbpaste or xclip)'
            print(msg, file=sys.stderr)
            yield UNSUPPORTED_PASTEBOARD
        copy_to_pasteboard = xclip
    else:
        copy_to_pasteboard = pboard

    name = args.name[0]
    account = account_for_slug(name)
    if account is None:
        yield UNRECOGNIZED_ACCOUNT

    password = account.password_query.order_by(Password.changed.desc()).first()
    if password is None:
        msg = 'error: no password is set for account:'
        print(msg, account.name, file=sys.stderr)
        yield UNSET_PASSWORD
    password = password.value

    if copy_to_pasteboard(password):
        print('error: failed to copy secret to pasteboard', file=sys.stderr)
        yield PASTEBOARD_COPY_FAILED

    line_fmt = 'secret on pasteboard for %is...'
    line = ''
    try:
        i = COPY_TIME
        while i > 0:
            sys.stdout.write('\r' + ' ' * len(line) + '\r')
            line = line_fmt % i
            sys.stdout.write(line)
            sys.stdout.flush()
            time.sleep(0.1)
            i -= 0.1
    finally:
        if copy_to_pasteboard('x'):
            msg = 'error: failed to copy garbage to pasteboard'
            print(msg, file=sys.stderr)
            yield PASTEBOARD_COPY_FAILED

    sys.stdout.write('\r' + ' ' * len(line) + '\r')
    print('pasteboard cleared')
