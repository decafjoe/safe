# -*- coding: utf-8 -*-
"""
test.test_pbkdf2
================

Tests the PBKDF2 function against the :rfc:`6070` test vectors.

:copyright: (c) 2015 Joe Strickler
:license: BSD, see LICENSE for more details
"""
import functools
import unittest

from safe import pbkdf2


cases = (
    ('password', 'salt', 1, 20, '0c60c80f961f0e71f3a9b524af6012062fe037a6'),
    ('password', 'salt', 2, 20, 'ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957'),
    ('password', 'salt', 4096, 20, '4b007901b765489abead49d926f721d065a429c1'),
    # This test causes a segfault.
    # (
    #     'password',
    #     'salt',
    #     16777216,
    #     20,
    #     'eefe3d61cd4da4e4e9945b3d6ba2158c2634e984',
    # ),
    (
        'passwordPASSWORDpassword',
        'saltSALTsaltSALTsaltSALTsaltSALTsalt',
        4096,
        25,
        '3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038',
    ),
    (
        'pass\0word',
        'sa\0lt',
        4096,
        16,
        '56fa6aa75548099dcc37d7f03425e0c3',
    ),
)


class PBKDF2Test(unittest.TestCase):
    def test(self):
        fn = functools.partial(pbkdf2, codec='hex_codec')
        for password, salt, iterations, key_length, expected_key in cases:
            actual_key = fn(password, salt, iterations, key_length)
            self.assertEqual(actual_key, expected_key)
