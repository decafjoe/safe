
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


Bcrypt
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


Fernet
======

.. autoexception:: FernetError
   :show-inheritance:
.. autoclass:: FernetSafeBackend
   :members:


GPG
===

.. autodata:: GPG_DEFAULT_CIPHER
.. autoexception:: GPGError
   :show-inheritance:
.. autoclass:: GPGSafeBackend
   :members:


NaCl
====

.. autoexception:: NaClError
   :show-inheritance:
.. autoclass:: NaClSafeBackend
   :members:


Plaintext
=========

.. autoclass:: PlaintextSafeBackend
