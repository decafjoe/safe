# -*- coding: utf-8 -*-
"""


:author: Joe Joyce <joe@decafjoe.com>
:copyright: Copyright (c) Joe Joyce and contributors, 2016-2017.
:license: BSD
"""
import sys

from clik import args, g, parser

from safe.cmd.delete import delete
from safe.ec import CANCELED, UNRECOGNIZED_ALIAS
from safe.model import Alias
from safe.util import prompt_bool


@delete
def alias():
    """Delete an alias."""
    parser.add_argument(
        'alias',
        help='alias to delete',
        nargs=1,
    )

    yield

    alias_value = args.alias[0]
    alias = Alias.query.filter_by(value=alias_value).first()
    if alias is None:
        print('error: alias: no alias named:', alias_value, file=sys.stderr)
        yield UNRECOGNIZED_ALIAS

    print()
    print('account:', alias.account.name)
    print('  alias:', alias_value)
    print()
    if prompt_bool('Delete this alias?', default=False):
        g.db.delete(alias)
        g.db.commit()
    else:
        yield CANCELED
