# -*- coding: utf-8 -*-
"""
Policy form definitions.

:author: Joe Joyce <joe@decafjoe.com>
:copyright: Copyright (c) Joe Joyce and contributors, 2016-2018.
:license: BSD
"""
from clik import g
from clik_wtforms import FieldList, Form, IntegerField, SelectField, \
    StringField
from wtforms.validators import InputRequired, NumberRange, Optional, \
    ValidationError

from safe.form import slug_validator
from safe.model import Policy
from safe.sgen import generate


class PolicyForm(Form):
    """Base form containing common fields, not meant to be used directly."""

    #: Short one-line description for the policy.
    #:
    #: :type: :class:`clik_wtforms.StringField`
    description = StringField(
        description='short one-line description for policy',
    )

    #: Frequency at which secret should be rotated.
    #:
    #: :type: :class:`clik_wtforms.IntegerField`
    frequency = IntegerField(
        description='number of days after which password should be rotated '
                    '(0 means never rotate) (default: '
                    '%s)' % Policy.DEFAULT_FREQUENCY,
        validators=[
            NumberRange(min=0, message='number must be 0 or greater'),
            Optional(),
        ],
    )

    #: Generator for secrets.
    #:
    #: :type: :class:`clik_wtforms.SelectField` of available
    #:        generators from :mod:`safe.sgen`
    generator = SelectField(
        choices=sorted(generate),
        description='method for auto-generating secrets for this policy '
                    '(default: %s)' % Policy.DEFAULT_GENERATOR,
    )

    #: Length of generated secrets.
    #:
    #: :type: :class:`clik_wtforms.IntegerField`
    length = IntegerField(
        description='length for auto-generated secrets (default: '
                    '%s)' % Policy.DEFAULT_LENGTH,
        validators=[
            NumberRange(min=1, message='number must be 1 or greater'),
            Optional(),
        ],
    )

    @staticmethod
    def get_short_arguments():
        """Return short arguments for the base fields."""
        return dict(
            d='description',
            f='frequency',
            g='generator',
            l='length',  # noqa: E741 (ambiguous var name makes sense here)
        )

    def update_policy(self, policy):
        """
        Modify ``policy`` based on the values from the form.

        :param safe.model.Policy policy: Policy to update
        """
        if self.description.data is not None:
            policy.description = self.description.data
        if self.frequency.data is not None:
            policy.frequency = self.frequency.data
        if self.generator.data is not None:
            policy.generator = self.generator.data
        if self.length.data is not None:
            policy.length = self.length.data


class NewPolicyForm(PolicyForm):
    """Form for creating new policies."""

    #: Characters that are not allowed in generated secrets.
    #:
    #: :type: :class:`clik_wtforms.FieldList` of
    #:        :class:`clik_wtforms.StringField`
    disallowed_characters = FieldList(
        StringField(),
        description='characters that may not be present in auto-generated '
                    'secrets',
    )

    #: Name for the policy.
    #:
    #: :type: :class:`clik_wtforms.StringField` validated by
    #:        :func:`safe.form.slug_validator`
    name = StringField(
        description='name for the policy',
        validators=[InputRequired(), slug_validator],
    )

    @classmethod
    def get_short_arguments(cls):
        """Return short arguments, merged with parent form short args."""
        d = super(NewPolicyForm, cls).get_short_arguments()
        d.update(dict(c='disallowed_characters', n='name'))
        return d

    def validate_name(self, field):
        """
        Validate that the new name does not already exist.

        :raises: :exc:`wtforms.validators.ValidationError` if new name is
                 the same as the name of an existing policy
        """
        if Policy.id_for_name(field.data) is not None:
            raise ValidationError('Policy with that name already exists')

    def create_policy(self):
        """
        Create a new policy based on the form data.

        Note that the new policy is added to the ``g.db`` session, but
        not committed.

        :return: Newly-created policy
        :rtype: :class:`safe.model.Policy`
        """
        policy = Policy(name=self.name.data)
        super(NewPolicyForm, self).update_policy(policy)
        chars = ''.join(sorted(set(''.join(self.disallowed_characters.data))))
        policy.disallowed_characters = chars
        g.db.add(policy)
        return policy


class UpdatePolicyForm(PolicyForm):
    """Form for updating an existing policy."""

    #: Character(s) to re-allow in generated secrets. This reverses
    #: the effect of :attr:`disallowed_characters`.
    #:
    #: :type: :class:`clik_wtforms.FieldList` of
    #:        :class:`clik_wtforms.StringField`
    allowed_characters = FieldList(
        StringField(),
        description='removes characters from the disallowed characters for '
                    'this policy (i.e. reverses the effect of '
                    '--disallowed-characters)',
    )

    #: Characters that are not allowed in generated secrets.
    #:
    #: :type: :class:`clik_wtforms.FieldList` of
    #:        :class:`clik_wtforms.StringField`
    disallowed_characters = FieldList(
        StringField(),
        description='characters that may not be part of the output',
    )

    #: New name for the policy.
    #:
    #: :type: :class:`clik_wtforms.StringField`
    new_name = StringField(
        description='new name for this policy (replaces current name)',
        metavar='NAME',
        validators=[slug_validator],
    )

    @classmethod
    def get_short_arguments(cls):
        """Return short arguments, merged with parent form short args."""
        d = super(UpdatePolicyForm, cls).get_short_arguments()
        d.update(dict(
            a='allowed_characters',
            c='disallowed_characters',
            n='new_name',
        ))
        return d

    def validate_new_name(self, field):
        """
        Validate new name.

        :param clik_wtforms.StringField field: New name field
        :raises: :exc:`wtforms.validators.ValidationError` if name is the same
                 as the current name, or already exists as a name of another
                 policy
        """
        field.change_name = False
        if field.data:
            if field.data == self.policy.name:
                msg = 'New name is the same as the current name'
                raise ValidationError(msg)
            if Policy.id_for_name(field.data) is not None:
                fmt = 'Policy with name "%s" already exists'
                raise ValidationError(fmt % field.data)
            field.change_name = True

    def bind_and_validate(self, policy, args=None):
        """Bind the ``policy`` to the form, then call the superclass."""
        self.policy = policy
        return super(UpdatePolicyForm, self).bind_and_validate(args)

    def update_policy(self):
        """
        Update the bound policy based on the data in the form.

        Note that this does not commit the changes.
        """
        super(UpdatePolicyForm, self).update_policy(self.policy)

        if self.new_name.change_name:
            self.policy.name = self.new_name.data

        allow, disallow = set(), set()
        for value in self.allowed_characters.data:
            for char in value:
                allow.add(char)
        for value in self.disallowed_characters.data:
            for char in value:
                disallow.add(char)
        chars = set(self.policy.disallowed_characters)
        for char in allow:
            if char in chars:
                chars.remove(char)
        for char in disallow:
            chars.add(char)
        self.policy.disallowed_characters = ''.join(sorted(chars))
