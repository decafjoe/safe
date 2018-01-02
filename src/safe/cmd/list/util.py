# -*- coding: utf-8 -*-
"""
Output utilities for the list command.

:author: Joe Joyce <joe@decafjoe.com>
:copyright: Copyright (c) Joe Joyce and contributors, 2016-2018.
:license: BSD
"""
NONE = '<none>'
NOT_SET = '<not set>'


def nullable(value):
    """Return :data:`NOT_SET` value if ``value`` is ``None``, else value."""
    if value is not None:
        return value
    return NOT_SET


def get_widths(rows, start_counts=None):
    """
    Return an list of integers of widest values for each column in ``rows``.

    If ``start_counts`` is not given, the return value is initialized to all
    zeroes.

    :param rows: Sequence of sequences representing rows
    :param list start_counts: Optional start counts for each column
    """
    rv = start_counts
    if rv is None:
        rv = [0] * len(rows[0])
    for row in rows:
        for i, cell in enumerate(row):
            n = len(str(cell))
            if n > rv[i]:
                rv[i] = n
    return rv


def print_table(headers, rows):
    """
    Print a table with ``headers`` and ``rows``.

    :param headers: Sequence of strings to be printed at the top of the table
    :param rows: Sequence of sequences representing the rows
    """
    widths = get_widths(rows, start_counts=[len(h) for h in headers])
    print(('    '.join(['%%-%is' % n for n in widths])) % headers)
    per = len(headers)
    fmt = '── '.join(['%s %s' for _ in range(per)]).rstrip('%s').rstrip()
    for row in rows:
        args = []
        for i, cell in enumerate(row):
            args.extend((cell, '─' * (widths[i] - len(str(cell)))))
        args.pop()
        print(fmt % tuple(args))


def print_detail(title, items, hack=None):
    """
    Print 'detail table' with ``title`` for ``items``.

    :param str title: Printed left-aligned
    :param items: Sequence of 2-tuples ``(field name, value)``, both of
                  which are strings
    :param hack: Ignore this dumb parameter
    """
    print(title)
    fmt = '  ┠%s┄┈ %s → %s'
    xmt = '  ┖%s┄┈ %s → %s'
    x = len(items) - 1
    width = get_widths(items)[0]
    for i, (key, value) in enumerate(items):
        bars = '─' * (width - len(key))
        if i == x:
            if hack:
                index, replacement = hack
                bars = bars[:index] + replacement + bars[index + 1:]
            print(xmt % (bars, key, value))
        else:
            print(fmt % (bars, key, value))


def sorted_by_name(query):
    """Return ``query`` sorted case-insensitively by object ``name``."""
    return sorted(query.all(), key=lambda obj: obj.name.lower())
