# -*- coding: utf-8 -*-
"""
New account command.

:author: Joe Joyce <joe@decafjoe.com>
:copyright: Copyright (c) Joe Joyce and contributors, 2016-2017.
:license: BSD
"""
from __future__ import print_function

import sys

from safe.cmd.new import new
from safe.ec import VALIDATION_ERROR
from safe.form.account import NewAccountForm


@new
def account():
    """Add an account to the database."""
    form = NewAccountForm()
    form.configure_parser()
    yield
    if not form.bind_and_validate():
        msg = 'error: there were validation error(s) with input value(s)'
        print(msg, file=sys.stderr)
        form.print_errors()
        yield VALIDATION_ERROR
    form.create_account()
    g.commit_and_save()
