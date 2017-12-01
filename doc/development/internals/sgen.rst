
===============
 ``safe.sgen``
===============

.. automodule:: safe.sgen

.. autoexception:: UnsurmountableConstraints

.. data:: generate
   :annotation: = AttributeDict()

   "Registry" for secret generators. Keys are the "friendly" name for
   the generator and the values are the generator functions.

   :type: :class:`dict` mapping ``str -> fn(int, str)``

.. autofunction:: generator

.. autofunction:: random_characters
