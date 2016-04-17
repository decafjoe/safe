
=========
 General
=========

.. module:: safe


Error Codes
===========

.. autodata:: ERR_CANCELED
.. autodata:: ERR_CP_OVERWRITE_CANCELED
.. autodata:: ERR_ECHO_NO_MATCH
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

.. autodata:: __version__
.. autodata:: CRYPTOGRAPHY_INSTALLED
   :annotation:
.. autodata:: NACL_INSTALLED
   :annotation:
.. autodata:: BACKEND_ENVVAR
.. autodata:: PATH_ENVVAR
.. autodata:: PREFERRED_BACKENDS


JSON
====

.. autodata:: date_re
   :annotation:
.. autofunction:: dump_json
.. autofunction:: load_json
.. autoclass:: JSONDatetimeDecoder(*args, **kwargs)
   :members:
   :show-inheritance:
.. autoclass:: JSONDatetimeEncoder(*args, **kwargs)
   :members:
   :private-members:
   :show-inheritance:


PBKDF2
======

.. autodata:: PBKDF2_DEFAULT_ITERATIONS
.. autodata:: PBKDF2_DEFAULT_SALT_LENGTH
.. autodata:: pbkdf2_pack_int
   :annotation: 
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
