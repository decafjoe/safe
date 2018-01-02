# -*- coding: utf-8 -*-
"""
Policy listing helpers.

:author: Joe Joyce <joe@decafjoe.com>
:copyright: Copyright (c) Joe Joyce and contributors, 2016-2018.
:license: BSD
"""
from safe.cmd.list.util import NONE, nullable, print_detail, print_table, \
    sorted_by_name


def get_policy_specs(policy):
    """
    Return short summary of secret generation params for ``policy``.

    :param safe.model.Policy policy: Policy for which to get specs
    :return: Human-friendly description of the policy
    :rtype: :class:`str`
    """
    if policy.frequency > 0:
        if policy.frequency == 1:
            change = 'changed every day'
        else:
            change = 'changed every %i days' % policy.frequency
    else:
        change = 'never changed'
    fmt = '%i chars from %s, %s'
    return fmt % (policy.length, policy.generator, change)


def list_policies(policies, verbosity):
    """
    Print policy information in ``verbosity`` level of detail.

    :param policies: SQLAlchemy query containing policies to be printed
    :type policies: :class:`sqlalchemy.orm.query.Query`
    :param int verbosity: Must be at least 0, anything past 1 is ignored,
                          higher means more information
    """
    print()
    if verbosity < 1:
        rows = []
        for p in sorted_by_name(policies):
            rows.append((p.name, p.generator, p.length, p.frequency))
        print_table(('NAME', 'GEN', 'LEN', 'FREQ'), rows)
    else:
        for policy in sorted_by_name(policies):
            chars = NONE
            if policy.disallowed_characters:
                chars = ''.join(sorted(policy.disallowed_characters))
            print_detail(
                policy.name, (
                    ('description', nullable(policy.description)),
                    ('specs', get_policy_specs(policy)),
                    ('∅ chars', chars),
                ),
            )
    print()
