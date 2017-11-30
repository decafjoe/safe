# -*- coding: utf-8 -*-
"""
Form definitions.

:author: Joe Joyce <joe@decafjoe.com>
:copyright: Copyright (c) Joe Joyce and contributors, 2016-2017.
:license: BSD
"""
from wtforms.validators import ValidationError

from safe.model import SLUG_RE, SLUG_VALIDATION_ERROR_MESSAGE


def slug_validator(_, field):
    if field.data and not SLUG_RE.search(field.data):
        raise ValidationError(SLUG_VALIDATION_ERROR_MESSAGE)
