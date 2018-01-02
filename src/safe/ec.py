# -*- coding: utf-8 -*-
"""
Exit codes for the application.

:author: Joe Joyce <joe@decafjoe.com>
:copyright: Copyright (c) Joe Joyce and contributors, 2016-2018.
:license: BSD
"""

#: User canceled the operation.
CANCELED = 10

#: Generic validation error.
VALIDATION_ERROR = 20

#: No account with given name.
NO_SUCH_ACCOUNT = 21

#: No policy with given name.
NO_SUCH_POLICY = 22

#: No policy with given identifier.
NO_SUCH_QUESTION = 23

#: GPG executable not found on system.
MISSING_GPG = 30

#: Decryption of GPG file failed.
DECRYPTION_FAILED = 31

#: Encryption of plaintext file failed.
ENCRYPTION_FAILED = 32

#: File is required, but missing.
MISSING_FILE = 40

#: File to be created already exists.
FILE_EXISTS = 41

#: Command requires file argument, which was not supplied.
FILE_ARGUMENT_REQUIRED = 42

#: Failed to securely delete a plaintext file with sensitive data.
#: (File deleted, but not in a secure manner.)
SRM_FAILED = 100

#: No password has been set for the account.
PASSWORD_NOT_SET = 101
