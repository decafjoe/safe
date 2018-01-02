# -*- coding: utf-8 -*-
"""
Account form definitions.

:author: Joe Joyce <joe@decafjoe.com>
:copyright: Copyright (c) Joe Joyce and contributors, 2016-2018.
:license: BSD
"""
from clik import g
from clik_wtforms import FieldList, Form, StringField
from wtforms.validators import InputRequired, ValidationError

from safe.form import slug_validator
from safe.model import Account, Alias, Code, Policy, Question


def policy_validator(_, field):
    """
    Validate that ``field.data`` is the name of a policy.

    :param field: Field to validate
    :type field: :class:`wtforms.fields.core.Field`
    :raises: :exc:`wtforms.validators.ValidationError` if data does not
             contain the name of a policy
    """
    if field.data and Policy.id_for_name(field.data) is None:
        raise ValidationError('No policy with that name')


class Operation(object):
    """Enum of "operation" types for certain form fields."""

    #: Update answer to a security question.
    A = 'a'

    #: Add a new item.
    ADD = ''

    #: Create a new security question.
    NEW = 'new'

    #: Update question part of a security question.
    Q = 'q'

    #: Remove an item.
    REMOVE = 'rm'

    #: Mark a backup code as used.
    USED = 'used'


class AccountForm(Form):
    """Base form containing common fields, not meant to be used directly."""

    #: Short one-line description for the account.
    #:
    #: :type: :class:`clik_wtforms.StringField`
    description = StringField(
        description='short one-line description for account',
    )

    #: Email associated with the account.
    #:
    #: :type: :class:`clik_wtforms.StringField`
    email = StringField(description='email associated with account')

    #: Name of the question policy for the account.
    #:
    #: :type: :class:`clik_wtforms.StringField` validated by
    #:        :func:`policy_validator`
    question_policy = StringField(
        description='policy to apply to security question answers for the '
                    'account',
        metavar='POLICY',
        validators=[policy_validator],
    )

    #: Name of the password policy for the account.
    #:
    #:
    #: :type: :class:`clik_wtforms.StringField` validated by
    #:        :func:`policy_validator`
    password_policy = StringField(
        description='policy to apply to passwords for the account',
        metavar='POLICY',
        validators=[policy_validator],
    )

    #: Username associated with the account.
    #:
    #: :type: :class:`clik_wtforms.StringField`
    username = StringField(description='username associated with the account')

    @staticmethod
    def get_short_arguments():
        """Return short arguments for the base fields."""
        return dict(d='description', e='email', u='username')

    def update_account(self, account):
        """
        Modify ``account`` based on the values from the form.

        :param safe.model.Account account: Account to update
        """
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
    """Form for creating new accounts."""

    #: Alias(es) associated with the account.
    #:
    #: :type: :class:`clik_wtforms.FieldList` of
    #:        :class:`clik_wtforms.StringField` validated by
    #:        :func:`safe.form.slug_validator`
    alias = FieldList(
        StringField(validators=[slug_validator]),
        description='alias for the account',
    )

    #: Backup code(s) associated with the account.
    #:
    #: :type: :class:`clik_wtforms.FieldList` of
    #:        :class:`clik_wtforms.StringField`
    code = FieldList(
        StringField(),
        description='backup code for the account',
    )

    #: Name for the account.
    #:
    #: :type: :class:`clik_wtforms.StringField` validated by
    #:        :func:`safe.form.slug_validator`
    name = StringField(
        description='name for the account',
        validators=[InputRequired(), slug_validator],
    )

    @classmethod
    def get_short_arguments(cls):
        """Return short arguments, merged with parent form short args."""
        d = super(NewAccountForm, cls).get_short_arguments()
        d.update(dict(a='alias', c='code', n='name'))
        return d

    def validate_alias(self, field):
        """
        Validate that aliases are unique.

        :raises: :exc:`wtforms.validators.ValidationError` if alias is
                 supplied twice or is the same as an existing account name
                 or alias
        """
        names = [self.name.data]
        for alias in field.data:
            if alias in names:
                fmt = 'Alias "%s" already supplied as name or other alias'
                raise ValidationError(fmt % alias)
            if Account.id_for_slug(alias):
                fmt = 'Account with name/alias "%s" already exists'
                raise ValidationError(fmt % alias)
            names.append(alias)

    def validate_name(self, field):
        """
        Validate that the new name does not already exist.

        :raises: :exc:`wtforms.validators.ValidationError` if new name is
                 the same as the name or alias of an existing account
        """
        if Account.id_for_slug(field.data):
            msg = 'Account with that name/alias already exists'
            raise ValidationError(msg)

    def create_account(self):
        """
        Create a new account based on the form data.

        Note that the new account object will be commited to ``g.db`` in
        order to get its id, which is required to create any new aliases
        or code instances in the database.

        :return: Newly-created account
        :rtype: :class:`safe.model.Account`
        """
        account = Account(name=self.name.data)
        super(NewAccountForm, self).update_account(account)
        g.db.add(account)
        g.db.commit()
        g.db.refresh(account)
        for alias in self.alias.data:
            g.db.add(Alias(account_id=account.id, value=alias))
        for code in self.code.data:
            g.db.add(Code(account_id=account.id, value=code))
        return account


class UpdateAccountForm(AccountForm):
    """Form for updating an existing account."""

    #: Alias(es) associated with the account. This is also used to
    #: remove aliases, by passing the value ``"rm:alias-name"``.
    #:
    #: :type: :class:`clik_wtforms.FieldList` of
    #:        :class:`clik_wtforms.StringField`
    alias = FieldList(
        StringField(),
        description='add or remove alias for the account',
    )

    #: Backup code(s) associated with the account. This can also be
    #: used to remove codes, by passing ``"rm:code"``, or mark a code
    #: as used, by passing ``"used:code"``.
    #:
    #: :type: :class:`clik_wtforms.FieldList` of
    #:        :class:`clik_wtforms.StringField`
    code = FieldList(
        StringField(),
        description='add, remove, or "mark as used" a backup code for the '
                    'account',
    )

    #: New name for the account.
    #:
    #: :type: :class:`clik_wtforms.StringField`
    new_name = StringField(
        description='new name for this account (replaces current name)',
        metavar='NAME',
        validators=[slug_validator],
    )

    #: Security question(s) associated with the account. This field
    #: supports the following "operations:"
    #:
    #: * Add new security question by passing ``"new:identifier"``
    #: * Remove question by passing ``"rm:identifier"``
    #: * Update question text by passing ``"q:identifier:new-text"``
    #: * Update answer text by passing ``"a:identifier:new-text"``
    #:
    #: :type: :class:`clik_wtforms.FieldList` of
    #:        :class:`clik_wtforms.StringField`
    question = FieldList(
        StringField(),
        description='add, remove, or update security questions/answers '
                    'associated with the account',
    )

    @classmethod
    def get_short_arguments(cls):
        """Return short arguments, merged with parent form short args."""
        d = super(UpdateAccountForm, cls).get_short_arguments()
        d.update(dict(a='alias', c='code', n='new_name', q='question'))
        return d

    def bind_and_validate(self, account, args=None):
        """Bind the ``account`` to the form, then call the superclass."""
        self.account = account
        return super(UpdateAccountForm, self).bind_and_validate(args)

    def validate_alias(self, field):
        """
        Validate alias operations.

        :param clik_wtforms.FieldList field: Alias field
        :raises: :exc:`wtforms.validators.ValidationError` if any operation
                 is invalid, or refers to a non-existant alias
        """
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
                    raise ValidationError(fmt % value)
                field.operations.append([op, value])

    def validate_code(self, field):
        """
        Validate code operations.

        :param clik_wtforms.FieldList field: Code field
        :raises: :exc:`wtforms.validators.ValidationError` if any operation
                 is invalid, or refers to a non-existant code
        """
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
                    raise ValidationError(fmt % value)
                field.operations.append([op, value])

    def validate_new_name(self, field):
        """
        Validate new name.

        :param clik_wtforms.StringField field: New name field
        :raises: :exc:`wtforms.validators.ValidationError` if name is the same
                 as the current name, or already exists as a name or alias
                 of another account
        """
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
        """
        Validate question operations.

        :param clik_wtforms.FieldList field: Question field
        :raises: :exc:`wtforms.validators.ValidationError` if any operation
                 is invalid, or refers to a non-existant question identifier
        """
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
                            if isinstance(other_subject, Question):
                                other_subject = other_subject.identifier
                            if subject == other_subject:
                                if op == other_op:
                                    fmt = 'Redundant "%s" operation for ' \
                                          'question with identifier "%s"'
                                    raise ValidationError(fmt % (op, subject))
                                if other_op == Operation.REMOVE:
                                    fmt = 'Question with identifier "%s" ' \
                                          'already scheduled for removal'
                                    raise ValidationError(fmt % subject)
                    else:
                        for other_op, other_subject, _ in field.operations:
                            if isinstance(other_subject, Question):
                                other_subject = other_subject.identifier
                            if subject == other_subject:
                                if op == other_op:
                                    fmt = 'Question with identifier "%s" ' \
                                          'already scheduled for removal'
                                    raise ValidationError(fmt % subject)
                                else:
                                    fmt = 'Question with identifier "%s" ' \
                                          'already scheduled to be updated'
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
                                           .filter_by(identifier=subject)\
                                           .first()
                    if question is not None:
                        fmt = 'Question with identifier "%s" is already ' \
                              'associated with this account'
                        raise ValidationError(fmt % subject)
                    if [op, subject, None] in field.operations:
                        fmt = 'Question with identifier "%s" already ' \
                              'scheduled for addition'
                        raise ValidationError(fmt % subject)
                    field.operations.append([op, subject, None])
                else:
                    raise ValidationError('Unknown operation "%s"' % op)
            else:
                raise ValidationError('No operation specified')

    def update_account(self):
        """
        Update the bound account based on the data in the form.

        Note that this does not commit the changes.
        """
        super(UpdateAccountForm, self).update_account(self.account)

        if self.new_name.change_name:
            self.account.name = self.new_name.data

        for op, subject in self.alias.operations:
            if op == Operation.ADD:
                g.db.add(Alias(account_id=self.account.id, value=subject))
            elif op == Operation.REMOVE:
                g.db.delete(subject)
            else:  # pragma: no cover (unreachable)
                raise Exception('unreachable')

        for op, subject in self.code.operations:
            if op == Operation.ADD:
                g.db.add(Code(account_id=self.account.id, value=subject))
            elif op == Operation.REMOVE:
                g.db.delete(subject)
            elif op == Operation.USED:
                subject.used = True
            else:  # pragma: no cover (unreachable)
                raise Exception('unreachable')

        for op, subject, details in self.question.operations:
            if op == Operation.A:
                subject.answer = ''
                if details:
                    subject.answer = details
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
                subject.question = ''
                if details:
                    subject.question = details
            elif op == Operation.REMOVE:
                g.db.delete(subject)
            else:  # pragma: no cover (unreachable)
                raise Exception('unreachable')
