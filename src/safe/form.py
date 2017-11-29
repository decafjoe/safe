# -*- coding: utf-8 -*-
"""
Form definitions.

:author: Joe Joyce <joe@decafjoe.com>
:copyright: Copyright (c) Joe Joyce and contributors, 2016-2017.
:license: BSD
"""
from clik import g
from clik_wtforms import FieldList, Form, StringField
from wtforms.validators import InputRequired, Regexp, ValidationError


from safe.model import Account, Alias, Code, Policy, Question, SLUG_RE, \
    SLUG_VALIDATION_ERROR_MESSAGE


def slug_validator(_, field):
    if field.data and not SLUG_RE.search(field.data):
        raise ValidationError(SLUG_VALIDATION_ERROR_MESSAGE)


def policy_validator(_, field):
    if field.data and Policy.id_for_name(field.data) is None:
        raise ValidationError('No policy named with that name')


class Operation(object):
    A = 'a'
    ADD = ''
    NEW = 'new'
    Q = 'q'
    REMOVE = 'rm'
    USED = 'used'


class AccountForm(Form):
    description = StringField(
        description='short one-line description for account',
    )
    email = StringField(description='email associated with account')
    question_policy = StringField(
        description='policy to apply to security question answers for the '
                    'account',
        metavar='POLICY',
        validators=[policy_validator],
    )
    password_policy = StringField(
        description='policy to apply to passwords for the account',
        metavar='POLICY',
        validators=[policy_validator],
    )
    username = StringField(description='username associated with the account')

    @staticmethod
    def get_short_arguments():
        return dict(d='description', e='email', u='username')

    def update(self, account):
        if self.description.data is not None:
            account.description = self.description.data
        if self.email.data is not None:
            account.email = self.email.data
        if self.question_policy.data is not None:
            policy_id = Policy.id_for_name(self.question_policy.data)
            account.question_policy_id = policy_id
        if self.password_policy.data is not None:
            policy_id = Policy.id_for_name(self.password_policy.data)
            account.password_policy_id = policy_id
        if self.username.data is not None:
            account.username = self.username.data


class NewAccountForm(AccountForm):
    alias = FieldList(
        StringField(validators=[slug_validator]),
        description='alias(es) for the account',
    )
    code = FieldList(
        StringField(),
        description='backup code(s) for the account',
    )
    name = StringField(
        description='name for the account',
        validators=[InputRequired(), slug_validator],
    )

    @classmethod
    def get_short_arguments(cls):
        d = super(NewAccountForm, cls).get_short_arguments()
        d.update(dict(a='alias', c='code', n='name'))
        return d

    def validate_alias(self, field):
        names = [self.name.data]
        for alias in field.data:
            if alias in names:
                fmt = 'Alias "%s" already supplied as name or other alias'
                raise ValidationError(fmt % alias)
            if Account.id_for_slug(field.data):
                fmt = 'Account with name/alias "%s" already exists'
                raise ValidationError(fmt % alias)
            names.append(alias)

    def validate_name(self, field):
        if Account.id_for_slug(field.data):
            msg = 'Account with that name/alias already exists'
            raise ValidationError(msg)

    def create_commit_and_save(self):
        account = Account(name=self.name.data)
        super(NewAccountForm, self).update(account)
        g.db.add(account)
        g.db.commit()
        g.db.refresh(account)
        for alias in self.alias.data:
            g.db.add(Alias(account_id=account.id, value=alias))
        for code in self.code.data:
            g.db.add(Code(account_id=account.id, value=code))
        g.commit_and_save()


class UpdateAccountForm(AccountForm):
    alias = FieldList(
        StringField(),
        description='add or remove alias for the account',
    )
    code = FieldList(
        StringField(),
        description='add, remove, or "mark as used" a backup code for the '
                    'account',
    )
    new_name = StringField(metavar='NAME', validators=[slug_validator])
    question = FieldList(
        StringField(),
        description='add, remove, or update security questions/answers '
                    'associated with the account',
    )

    @classmethod
    def get_short_arguments(cls):
        d = super(UpdateAccountForm, cls).get_short_arguments()
        d.update(dict(a='alias', c='code', n='new_name', q='question'))
        return d

    def bind_and_validate(self, account):
        self.account = account
        return super(UpdateAccountForm, self).bind_and_validate()

    def validate_alias(self, field):
        field.operations = []
        for value in field.data:
            if ':' in value:
                op, subject = value.split(':', 1)
                if op == Operation.REMOVE:
                    obj = self.account.alias_query\
                                      .filter_by(value=subject)\
                                      .first()
                    if obj is None:
                        fmt = 'No alias named "%s" associated with account'
                        raise ValidationError(fmt % subject)
                    if [op, obj] in field.operations:
                        fmt = 'Alias "%s" already scheduled for removal'
                        raise ValidationError(fmt % subject)
                    field.operations.append([op, obj])
                else:
                    raise ValidationError('Unknown operation "%s"' % op)
            else:
                op = Operation.ADD
                if Account.id_for_slug(value):
                    fmt = 'Account with name/alias "%s" already exists'
                    raise ValidationError(fmt % value)
                if [op, value] in field.operations:
                    fmt = 'Alias "%s" already scheduled for addition'
                    raise ValidationError(fmt % subject)
                field.operations.append([op, value])

    def validate_code(self, field):
        field.operations = []
        for value in field.data:
            if ':' in value:
                op, subject = value.split(':', 1)
                if op in (Operation.REMOVE, Operation.USED):
                    obj = self.account.code_query\
                                      .filter_by(value=subject)\
                                      .first()
                    if obj is None:
                        fmt = 'No code "%s" associated with account'
                        raise ValidationError(fmt % subject)
                    if [Operation.REMOVE, obj] in field.operations:
                        fmt = 'Code "%s" already scheduled for removal'
                        raise ValidationError(fmt % subject)
                    if [Operation.USED, obj] in field.operations:
                        fmt = 'Code "%s" already scheduled to be marked used'
                        raise ValidationError(fmt % subject)
                    field.operations.append([op, obj])
                else:
                    raise ValidationError('Unknown operation "%s"' % op)
            else:
                op = Operation.ADD
                code = self.account.code_query.filter_by(value=value).first()
                if code is not None:
                    fmt = 'Code "%s" is already associated with this account'
                    raise ValidationError(fmt % value)
                if [op, value] in field.operations:
                    fmt = 'Code "%s" already scheduled for addition'
                    raise ValidationError(fmt % subject)
                field.operations.append([op, value])

    def validate_new_name(self, field):
        field.change_name = False
        if field.data:
            if field.data == self.account.name:
                msg = 'New name is the same as the current name'
                raise ValidationError(msg)
            if Account.id_for_slug(field.data) is not None:
                fmt = 'Account with name/alias "%s" already exists'
                raise ValidationError(fmt % field.data)
            field.change_name = True

    def validate_question(self, field):
        field.operations = []
        for value in field.data:
            if ':' in value:
                op, subject = value.split(':', 1)
                if op in (Operation.A, Operation.Q, Operation.REMOVE):
                    details = None
                    if op in (Operation.A, Operation.Q):
                        if ':' in subject:
                            subject, details = subject.split(':', 1)
                        for other_op, other_subject, _ in field.operations:
                            if subject == other_subject:
                                if op == other_op:
                                    fmt = 'Redundant "%s" operation for ' \
                                          'question with identifier "%s"'
                                    raise ValidationError(fmt % (op, subject))
                                if other_op == Operation.REMOVE:
                                    fmt = 'Question "%s" already scheduled ' \
                                          'for removal'
                                    raise ValidationError(fmt % subject)
                    else:
                        for other_op, other_subject, _ in field.operations:
                            if subject == other_subject:
                                if op == other_op:
                                    fmt = 'Question "%s" already scheduled ' \
                                          'for removal'
                                    raise ValidationError(fmt % subject)
                                else:
                                    fmt = 'Question "%s" already scheduled ' \
                                          'to be updated'
                                    raise ValidationError(fmt % subject)
                    obj = self.account.question_query\
                                      .filter_by(identifier=subject)\
                                      .first()
                    if obj is None:
                        fmt = 'No question with identifier "%s" associated ' \
                              'with account'
                        raise ValidationError(fmt % subject)
                    field.operations.append([op, obj, details])
                elif op == Operation.NEW:
                    question = self.account.question_query\
                                           .filter_by(identifier=value)\
                                           .first()
                    if question is not None:
                        fmt = 'Question with identifier "%s" is already ' \
                              'associated with this account'
                        raise ValidationError(fmt % value)
                    if [op, value, None] in field.operations:
                        fmt = 'Question with identifier "%s" already ' \
                              'scheduled for addition'
                        raise ValidationError(fmt % subject)
                    field.operations.append([op, value, None])
                else:
                    raise ValidationError('Unknown operation "%s"' % op)
            else:
                raise ValidationError('No operation specified')

    def update_commit_and_save(self):
        super(UpdateAccountForm, self).update(self.account)

        if self.new_name.change_name:
            self.account.name = self.new_name.data
            g.db.add(self.account)

        for op, subject in self.alias.operations:
            if op == Operation.ADD:
                g.db.add(Alias(account_id=self.account.id, value=subject))
            elif op == Operation.REMOVE:
                g.db.delete(subject)
            else:
                raise Exception('unreachable')

        for op, subject in self.code.operations:
            if op == Operation.ADD:
                g.db.add(Code(account_id=self.account.id, value=subject))
            elif op == Operation.REMOVE:
                g.db.delete(subject)
            elif op == Operation.USED:
                subject.used = True
                g.db.add(subject)
            else:
                raise Exception('unreachable')

        for op, subject, details in self.question.operations:
            if op == Operation.A:
                if details:
                    subject.answer = details
                    g.db.add(subject)
            elif op == Operation.NEW:
                question, answer = '', ''
                if details:
                    question, answer = details
                g.db.add(Question(
                    account_id=self.account.id,
                    answer=answer,
                    identifier=subject,
                    question=question,
                ))
            elif op == Operation.Q:
                if details:
                    subject.question = details
                    g.db.add(subject)
            elif op == Operation.REMOVE:
                g.db.delete(subject)
            else:
                raise Exception('unreachable')

        g.commit_and_save()
