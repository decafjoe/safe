
===========
 Internals
===========

.. automodule:: safe


Error Codes
===========

.. autodata:: ERR_CANCELED
.. autodata:: ERR_CP_OVERWRITE_CANCELED
.. autodata:: ERR_PB_UNSUPPORTED_PLATFORM
.. autodata:: ERR_PB_INVALID_TIME
.. autodata:: ERR_PB_NO_MATCH
.. autodata:: ERR_PB_PUT_SECRET_FAILED
.. autodata:: ERR_PB_PUT_GARBAGE_FAILED


Base Exceptions
===============

.. autoexception:: SafeError
   :show-inheritance:
.. autoexception:: SafeCryptographyError
   :show-inheritance:


Miscellaneous
=============

.. autodata:: BACKEND_ENVVAR
.. autodata:: PATH_ENVVAR
.. autodata:: PREFERRED_BACKENDS


JSON
====

.. autofunction:: dump_json
.. autofunction:: load_json
.. autoclass:: JSONDatetimeDecoder
   :members:
.. autoclass:: JSONDatetimeEncoder
   :members:


PBKDF2
======

.. autodata:: PBKDF2_DEFAULT_ITERATIONS
.. autodata:: PBKDF2_DEFAULT_SALT_LENGTH
.. autofunction:: pbkdf2


Utilities
=========

.. autofunction:: expand_path
.. autofunction:: generate_key
.. autofunction:: get_executable
.. autofunction:: prompt_boolean
.. autofunction:: prompt_for_new_password
.. autofunction:: prompt_until_decrypted
.. autofunction:: prompt_until_decrypted_pbkdf2


PasteboardDriver: Base
======================

.. autodata:: pasteboard_drivers
   :annotation:
.. autofunction:: get_pasteboard_driver
.. autofunction:: pasteboard_driver
.. autoclass:: PasteboardDriver
   :members:


PasteboardDriver: pbcopy
========================

.. autodata:: PBCOPY
   :annotation:
.. autodata:: PBPASTE
   :annotation:
.. autoclass:: PbcopyPasteboardDriver

   .. autoattribute:: specificity


PasteboardDriver: xclip
=======================

.. autodata:: XCLIP
   :annotation:
.. autoclass:: XclipPasteboardDriver

   .. autoattribute:: specificity


SafeBackend: Base
=================

.. autodata:: backend_map
   :annotation:
.. autofunction:: backend
.. autofunction:: get_supported_backend_names
.. autoexception:: BackendNameConflictError
   :show-inheritance:
.. autoclass:: SafeBackend
   :members:


SafeBackend: Bcrypt
===================

.. autodata:: BCRYPT_DEFAULT_OVERWRITES
.. autoexception:: BcryptError
   :show-inheritance:
.. autoexception:: BcryptCryptographyError
   :show-inheritance:
.. autoexception:: BcryptFilenameError
   :show-inheritance:
.. autoclass:: BcryptSafeBackend
   :members:


SafeBackend: Fernet
===================

.. autoexception:: FernetError
   :show-inheritance:
.. autoclass:: FernetSafeBackend
   :members:


SafeBackend: GPG
================

.. autodata:: GPG_DEFAULT_CIPHER
.. autoexception:: GPGError
   :show-inheritance:
.. autoclass:: GPGSafeBackend
   :members:


SafeBackend: NaCl
=================

.. autoexception:: NaClError
   :show-inheritance:
.. autoclass:: NaClSafeBackend
   :members:


SafeBackend: Plaintext
======================

.. autoclass:: PlaintextSafeBackend
