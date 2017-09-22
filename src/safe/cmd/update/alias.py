# -*- coding: utf-8 -*-
"""


:author: Joe Joyce <joe@decafjoe.com>
:copyright: Copyright (c) Joe Joyce and contributors, 2016-2017.
:license: BSD
"""
import sys

from clik import args, g, parser

from safe.cmd.update import update
from safe.cmd.util import account_for_slug
from safe.db import slug_error
from safe.ec import UNRECOGNIZED_ALIAS, VALIDATION_ERROR
from safe.model import Alias


@update
def alias():
    """Rename an alias."""
    parser.add_argument(
        'alias',
        help='alias to rename',
        nargs=1,
    )
    parser.add_argument(
        'new-alias',
        help='new name for the alias',
        nargs=1,
    )

    yield

    current_alias = args.alias[0]
    new_alias = getattr(args, 'new-alias')[0]

    alias = Alias.query.filter_by(value=current_alias).first()
    if alias is None:
        print('error: unrecognized alias:', current_alias, file=sys.stderr)
        yield UNRECOGNIZED_ALIAS

    if current_alias == new_alias:
        print('error: new alias is the same as old alias', file=sys.stderr)
        yield VALIDATION_ERROR

    msg = slug_error(new_alias)
    if msg:
        print('error: new-alias:', msg, file=sys.stderr)
        yield VALIDATION_ERROR

    account = account_for_slug(new_alias)
    if account:
        fmt = 'error: new-alias: alias "%s" already in use for account "%s"'
        print(fmt % (new_alias, account.name), file=sys.stderr)
        yield VALIDATION_ERROR

    alias.value = new_alias
    g.db.add(alias)
    g.db.commit()
