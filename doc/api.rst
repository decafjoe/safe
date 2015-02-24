
=====
 API
=====

.. automodule:: safe
.. autoexception:: SafeError


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

.. autofunction:: generate_key
.. autofunction:: get_executable
.. autofunction:: prompt_for_new_password
.. autofunction:: prompt_until_decrypted
.. autofunction:: prompt_until_decrypted_pbkdf2


SafeBackend: Base
=================

.. autodata:: backend_map
   :annotation:
.. autofunction:: backend
.. autoclass:: SafeBackend
   :members:


SafeBackend: Bcrypt
===================

.. autodata:: BCRYPT
   :annotation:
.. autodata:: BCRYPT_DEFAULT_OVERWRITES
.. autoexception:: BcryptError
.. autoclass:: BcryptSafeBackend
   :members:


SafeBackend: Fernet
===================

.. autoclass:: FernetSafeBackend


SafeBackend: GPG
================

.. autodata:: GPG
   :annotation:
.. autodata:: GPG_DEFAULT_CIPHER
.. autoclass:: GPGSafeBackend
   :members:


SafeBackend: NaCl
=================

.. autoclass:: NaClSafeBackend
   :members:


SafeBackend: Plaintext
======================

.. autoclass:: PlaintextSafeBackend
