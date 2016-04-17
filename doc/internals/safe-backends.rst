
===============
 Safe Backends
===============


.. module:: safe

.. autodata:: backend_map
   :annotation:
.. autofunction:: backend
.. autofunction:: get_supported_backend_names
.. autoexception:: BackendNameConflictError
   :show-inheritance:
.. autoclass:: SafeBackend
   :members:


bcrypt
======

.. autodata:: BCRYPT_DEFAULT_OVERWRITES
.. autoexception:: BcryptError
   :show-inheritance:
.. autoexception:: BcryptCryptographyError
   :show-inheritance:
.. autoexception:: BcryptFilenameError
   :show-inheritance:
.. autoclass:: BcryptSafeBackend
   :members:
   :show-inheritance:


Fernet
======

.. autoexception:: FernetCryptographyError
   :show-inheritance:
.. autoclass:: FernetSafeBackend
   :members:
   :show-inheritance:


GPG
===

.. autodata:: GPG_DEFAULT_CIPHER
.. autoexception:: GPGCryptographyError
   :show-inheritance:
.. autoclass:: GPGSafeBackend
   :members:
   :show-inheritance:


NaCl
====

.. autoexception:: NaClCryptographyError
   :show-inheritance:
.. autoclass:: NaClSafeBackend
   :members:
   :show-inheritance:


Plaintext
=========

.. autoclass:: PlaintextSafeBackend
   :members:
   :show-inheritance:
