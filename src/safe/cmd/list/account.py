# -*- coding: utf-8 -*-
"""
Account listing helpers.

:author: Joe Joyce <joe@decafjoe.com>
:copyright: Copyright (c) Joe Joyce and contributors, 2016-2018.
:license: BSD
"""
from safe.cmd.list.policy import get_policy_specs
from safe.cmd.list.util import NONE, NOT_SET, nullable, print_detail, \
    print_table, sorted_by_name
from safe.model import Password, Question


#: :meth:`datetime.datetime.strftime` format in which dates will be
#: printed.
#:
#: :type: :class:`str`
DATE_FORMAT = '%Y-%m-%d'

#: "Template" for question subtrees for prolix output.
#:
#: :type: :class:`str`
prolix_question_fmt = """
    ┃  ┏─┄┈ id → %(identifier)s
    %(box_1)s──╋──┄┈ q → %(question)s
    %(box_2)s  ┖──┄┈ a → %(answer)s
""".strip()


def get_common_details(account):
    """
    Return details common to both verbosity levels.

    :param safe.model.Account account: Account for which to get details
    :return: Sequence of 2-tuples with details for the UI
    :rtype: :func:`tuple` of 2-tuples ``(field name, info)`` where both
            items are strings
    """
    aliases = NONE
    if account.aliases:
        aliases = ', '.join([alias.value for alias in account.aliases])

    password = NOT_SET
    password_count = account.password_query.count()
    if password_count > 0:
        if password_count == 1:
            changed = account.password_query.all()[0].changed
            password = 'set on %s' % changed.strftime(DATE_FORMAT)
        else:
            fmt = 'changed %i times (first: %s) (last: %s)'

            def date(order_by):
                pw = account.password_query.order_by(order_by).limit(1).first()
                return pw.changed.strftime(DATE_FORMAT)

            first = date(Password.changed)
            last = date(Password.changed.desc())
            password = fmt % (password_count, first, last)

    return (
        ('description', nullable(account.description)),
        ('aliases', aliases),
        ('username', nullable(account.username)),
        ('email', nullable(account.email)),
        ('password', password),
    )


def get_verbose_details(account):
    """
    Return details for verbose output.

    :param safe.model.Account account: Account for which to get details
    :return: Sequence of 2-tuples with details for the UI
    :rtype: :func:`tuple` of 2-tuples ``(field name, info)`` where both
            items are strings
    """
    questions = 'no questions'
    questions_count = account.question_query.count()
    if questions_count > 0:
        questions = '%i question' % questions_count
        if questions_count > 1:
            questions += 's'

    codes = 'no backup codes'
    codes_count = account.code_query.count()
    if codes_count > 0:
        codes = '%i backup code' % codes_count
        if codes_count > 1:
            codes += 's'
        used_codes = 'none used'
        used_codes_count = account.code_query.filter_by(used=True).count()
        if used_codes_count > 0:
            used_codes = '%i used' % used_codes_count
        codes += ' (%s)' % used_codes

    security = '%s, %s' % (questions, codes)

    fmt = 'password is %s, question is %s'
    password_policy = '<not set>'
    if account.password_policy:
        password_policy = '"%s"' % account.password_policy.name
    question_policy = '<not set>'
    if account.question_policy:
        question_policy = '"%s"' % account.question_policy.name
    policies = fmt % (password_policy, question_policy)

    return (('security', security), ('policies', policies))


def get_prolix_details(account):
    """
    Return details for prolix output.

    :param safe.model.Account account: Account for which to get details
    :return: Sequence of 2-tuples with details for the UI
    :rtype: :func:`tuple` of 2-tuples ``(field name, info)`` where both
            items are strings
    """
    active_codes = NONE
    active_codes_query = account.code_query.filter_by(used=False)
    if active_codes_query.count() > 0:
        codes = sorted([code.value for code in active_codes_query.all()])
        active_codes = ', '.join(codes)

    used_codes = NONE
    used_codes_query = account.code_query.filter_by(used=True)
    if used_codes_query.count() > 0:
        codes = sorted([code.value for code in used_codes_query.all()])
        used_codes = ', '.join(codes)

    password_policy = 'policy is %s' % NOT_SET
    if account.password_policy:
        p = account.password_policy
        password_policy = '%s (%s)' % (p.name, get_policy_specs(p))

    question_policy = 'policy is %s' % NOT_SET
    if account.question_policy:
        p = account.question_policy
        question_policy = '%s (%s)' % (p.name, get_policy_specs(p))

    question_count = account.question_query.count()

    return (
        ('active codes', active_codes),
        ('used codes', used_codes),
        ('passwords', password_policy),
        ('answers', question_policy),
        ('questions', str(question_count)),
    )


def print_verbosely(account):
    """
    Print verbose information for ``account``.

    :param safe.model.Account account: Account for which to print verbose info
    """
    common_details = get_common_details(account)
    extra_details = get_verbose_details(account)
    print_detail(account.name, common_details + extra_details)


def print_prolixly(account):
    """
    Print prolix information for ``account``.

    :param safe.model.Account account: Account for which to print prolix info
    """
    common_details = get_common_details(account)
    extra_details = get_prolix_details(account)
    hack = None
    if account.question_query.count() > 0:
        hack = (1, '┰')
    print_detail(account.name, common_details + extra_details, hack=hack)
    print_questions(account)


def print_questions(account):
    """
    Print question subtree for ``account``.

    :param safe.model.Account account: Account for which to print question
                                       subtree
    """
    i, n = 0, account.question_query.count()
    for question in account.question_query.order_by(Question.identifier).all():
        i += 1
        box_1 = '┠'
        box_2 = '┃'
        if i == n:
            box_1 = '┖'
            box_2 = ' '
        print('    %s' % prolix_question_fmt % dict(
            answer=question.answer,
            box_1=box_1,
            box_2=box_2,
            identifier=question.identifier,
            question=question.question,
        ))


def list_accounts(accounts, verbosity):
    """
    Print account information in ``verbosity`` level of detail.

    :param accounts: SQLAlchemy query containing accounts to be printed
    :type accounts: :class:`sqlalchemy.orm.query.Query`
    :param int verbosity: Must be at least 0, anything past 2 is ignored,
                          higher means more information
    """
    print()
    if verbosity < 1:
        rows = []
        for a in sorted_by_name(accounts):
            rows.append((a.name, nullable(a.username), nullable(a.email)))
        print_table(('NAME', 'USERNAME', 'EMAIL'), rows)
    elif verbosity < 2:
        for account in sorted_by_name(accounts):
            print_verbosely(account)
    else:
        for account in sorted_by_name(accounts):
            print_prolixly(account)
    print()
