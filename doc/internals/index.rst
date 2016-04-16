
===========
 Internals
===========

.. automodule:: safe

.. toctree::
   :maxdepth: 2

   safe-backends
   import-strategies
   pasteboard-drivers


Error Codes
===========

.. autodata:: ERR_CANCELED
.. autodata:: ERR_CP_OVERWRITE_CANCELED
.. autodata:: ERR_NEW_UNKNOWN_CREATED_DATE
.. autodata:: ERR_NEW_UNKNOWN_MODIFIED_DATE
.. autodata:: ERR_NEW_IMPORT_STRATEGY_FAILED
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
