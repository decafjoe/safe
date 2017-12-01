
===============
 ``safe.clip``
===============

.. automodule:: safe.clip

.. autoexception:: ClipboardError

.. autodata:: clipboard_drivers
   :annotation:

.. autoclass:: Registry
   :show-inheritance:
   :members:

.. autoclass:: Driver
   :members:
   :exclude-members: name, param, parameters, precedence, supported

   .. autoattribute:: name
      :annotation:

   .. autoattribute:: supported
      :annotation:

   .. autoattribute:: precedence
      :annotation:

   .. autoattribute:: parameters
      :annotation:

   .. autoattribute:: param
      :annotation:

.. autoclass:: Pasteboard
   :show-inheritance:
   :members:
   :exclude-members: pbcopy, pbpaste, supported

   .. autoattribute:: pbcopy
      :annotation:

   .. autoattribute:: pbcopy
      :annotation:

   .. autoattribute:: supported
      :annotation:

.. autoclass:: Xclip
   :show-inheritance:
   :members:
   :exclude-members: xclip, supported

   .. autoattribute:: xclip
      :annotation:

   .. autoattribute:: supported
      :annotation:

.. autofunction:: sorted_by_precedence

.. autofunction:: run
