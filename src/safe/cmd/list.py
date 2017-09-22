# -*- coding: utf-8 -*-
"""


:author: Joe Joyce <joe@decafjoe.com>
:copyright: Copyright (c) Joe Joyce and contributors, 2016-2017.
:license: BSD
"""
from clik import args, g, parser
from sqlalchemy import or_

from safe.app import safe
from safe.model import Account, Alias, Code, Password, Question


NOT_SET = '<not set>'
DATE_FORMAT = '%Y-%m-%d'


summary_fmt = """
%(name)s %(name_box)s─┄┈ %(username)s %(username_box)s─┄┈ %(email)s
""".strip()

detail_fmt = """
  ┠─┄┈ description → %(description)s
  ┠─────┄┈ aliases → %(aliases)s
  ┠──┄┈ pw changed → %(changed)s
  ┠───┄┈ pw policy → %(policy)s
  ┠───────┄┈ codes → %(codes)s
  ┖───┄┈ questions → %(questions)s
""".strip()

verbose_item_fmt = """
  ┃    %(box)s──────────┄┈ %(value)s
""".strip()

verbose_policy_fmt = """
  ┃  ┠─────┄┈ desc → %(description)s
  ┃  ┠───┄┈ length → %(length)s
  ┃  ┠─────┄┈ freq → %(frequency)s
  ┃  ┖──┈ ex chars → %(disallowed_chars)s
""".strip()

verbose_question_fmt = """
     ┃
     ┃  ┏────┄┈ id → %(identifier)s
     %(box_1)s──╋─────┄┈ q → %(question)s
     %(box_2)s  ┖─────┄┈ a → %(answer)s
""".strip()

verbose_fmt = """
  ┠─┄┈ description → %(description)s
  ┠─────┄┈ aliases → %(aliases)s
  ┠──┄┈ pw changed → %(changed)s
  ┃
  ┠──%(policy_box)s┄┈ pw policy → %(policy)s%(policy_content)s
  ┃
  ┠────%(codes_box)s──┄┈ codes → %(codes)s%(codes_content)s
  ┃
  ┖──%(questions_box)s┄┈ questions → %(questions)s%(questions_content)s
""".strip()


@safe(name='list', alias='ls')
def list_():
    """List accounts and their settings."""
    parser.add_argument(
        'name',
        nargs='*',
        help='name(s) to list (will substring match against account names '
             'and aliases unless -s/--strict is supplied)',
    )
    parser.add_argument(
        '-v',
        '--verbose',
        action='count',
        default=0,
        help='list more detailed information about each account (may be '
             'supplied multiple times)',
    )
    parser.add_argument(
        '-s',
        '--strict',
        action='store_true',
        default=False,
        help='match names/aliases strictly',
    )

    yield

    accounts_query = Account.query
    if args.name:
        clauses = []
        for name in args.name:
            if args.strict:
                clauses.extend((Account.name == name, Alias.value == name))
            else:
                like = '%%%s%%' % name
                account_like = Account.name.like(like)
                alias_like = Alias.value.like(like)
                clauses.extend((account_like, alias_like))
        accounts_query = accounts_query.outerjoin(Account.aliases)\
                                       .filter(or_(*clauses))

    accounts_count = accounts_query.count()
    if accounts_count == 1:
        msg = '1 account'
    else:
        msg = '%i accounts' % accounts_count
    print(msg)
    if accounts_count == 0:
        yield

    accounts = list(accounts_query.order_by(Account.name))

    names = [account.name for account in accounts]
    max_name_len = max([len(name) for name in names])

    emails = [account.email for account in accounts if account.email]
    if any(not account.email for account in accounts):
        emails.append(NOT_SET)
    max_email_len = max([len(email) for email in emails])

    usernames = [account.username for account in accounts if account.username]
    if any(not account.username for account in accounts):
        usernames.append(NOT_SET)
    max_username_len = max([len(username) for username in usernames])

    print()
    for account in accounts:
        email = account.email
        if email is None:
            email = NOT_SET
        username = account.username
        if username is None:
            username = NOT_SET
        summary = summary_fmt % dict(
            email=email,
            name=account.name,
            name_box='─' * (max_name_len - len(account.name)),
            username=username,
            username_box='─' * (max_username_len - len(username)),
        )
        print(summary)
        if args.verbose > 0:
            description = '<none>'
            if account.description:
                description = account.description

            change_summary = '<never>'
            change_query = g.db.query(Password.changed)\
                               .join(Account)\
                               .filter(Account.id == account.id)\
                               .order_by(Password.changed.desc())
            change_dates = [row[0] for row in change_query]
            change_count = len(change_dates)
            if change_count > 0:
                change_summary = change_dates[0].strftime(DATE_FORMAT)
                if change_count > 1:
                    fmt = ' (%i times total since %s)'
                    first_change = change_dates[-1].strftime('%m/%Y')
                    change_summary += fmt % (change_count, first_change)

            password_policy = NOT_SET
            if account.password_policy_id is not None:
                password_policy = account.password_policy.name

            aliases = '<none>'
            alias_query = g.db.query(Alias.value)\
                              .join(Account)\
                              .filter(Account.id == account.id)\
                              .order_by(Alias.value)
            if alias_query.count() > 0:
                aliases = ', '.join([alias.value for alias in alias_query])

            codes = '<none>'
            codes_query = g.db.query(Code.value)\
                              .join(Account)\
                              .filter(Account.id == account.id)\
                              .order_by(Code.value)
            codes_count = codes_query.count()
            if codes_count > 0:
                codes = str(codes_count)

            questions = '<none>'
            questions_query = account.question_query\
                                     .order_by(Question.identifier)
            questions_count = questions_query.count()
            if questions_count > 0:
                questions = str(questions_count)

            if account.question_policy_id is not None:
                policy_name = account.question_policy.name
                questions += ' (policy: %s)' % policy_name

            if args.verbose > 1:
                policy_box = '─'
                policy_content = ''
                if account.password_policy_id is not None:
                    policy_box = '┰'
                    policy = account.password_policy
                    frequency = '<never>'
                    if policy.frequency > 0:
                        frequency = 'every %i days' % policy.frequency
                    chars = '<none>'
                    if policy.disallowed_characters:
                        chars = sorted(policy.disallowed_characters)
                    policy_content = '\n  %s' % verbose_policy_fmt % dict(
                        description=policy.description,
                        disallowed_chars=chars,
                        frequency=frequency,
                        length=policy.length,
                    )

                codes_box = '─'
                codes_content = ''
                if codes_count > 0:
                    codes_box = '┰'
                    for i, row in enumerate(list(codes_query)):
                        box = '┠'
                        if i == (codes_count - 1):
                            box = '┖'
                        item = verbose_item_fmt % dict(box=box, value=row[0])
                        codes_content += '\n  %s' % item

                questions_box = '─'
                questions_content = ''
                if questions_count > 0:
                    questions_box = '┰'
                    for i, question in enumerate(questions_query):
                        box_1 = '┠'
                        box_2 = '┃'
                        if i == (questions_count - 1):
                            box_1 = '┖'
                            box_2 = ' '
                        content = verbose_question_fmt % dict(
                            answer=question.answer,
                            box_1=box_1,
                            box_2=box_2,
                            identifier=question.identifier,
                            question=question.question,
                        )
                        questions_content += '\n     %s' % content

                out = verbose_fmt % dict(
                    aliases=aliases,
                    changed=change_summary,
                    codes=codes,
                    codes_box=codes_box,
                    codes_content=codes_content,
                    description=description,
                    policy=password_policy,
                    policy_box=policy_box,
                    policy_content=policy_content,
                    questions=questions,
                    questions_box=questions_box,
                    questions_content=questions_content,
                )
            else:
                out = detail_fmt % dict(
                    aliases=aliases,
                    changed=change_summary,
                    codes=codes,
                    description=description,
                    policy=password_policy,
                    questions=questions,
                )

            print(' ', out)
            print()
    print()
