# -*- coding: utf-8 -*-
"""
Form definitions.

:author: Joe Joyce <joe@decafjoe.com>
:copyright: Copyright (c) Joe Joyce and contributors, 2016-2018.
:license: BSD
"""
from wtforms.validators import ValidationError

from safe.model import SLUG_RE, SLUG_VALIDATION_ERROR_MESSAGE


def slug_validator(_, field):
    """
    Validate that ``field.data`` is a slug.

    :param field: Field to validate
    :type field: :class:`wtforms.fields.core.Field`
    :raises: :exc:`wtforms.validators.ValidationError` if data is invalid
    """
    if field.data and not SLUG_RE.search(field.data):
        raise ValidationError(SLUG_VALIDATION_ERROR_MESSAGE)
