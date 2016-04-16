
===================
 Import Strategies
===================

.. module:: safe

.. autodata:: import_strategy_map
   :annotation:
.. autofunction:: import_strategy
.. autoclass:: ImportStrategy
   :members:

   .. automethod:: __call__

.. autoexception:: ImportStrategyFailedError
.. autoexception:: ImportStrategyNameConflictError


Generate
========

.. autoclass:: GenerateImportStrategy
   :members:


Interactively Generate
======================

.. autoclass:: InteractivelyGenerateImportStrategy
   :members:


Pasteboard
==========

.. autoclass:: PasteboardImportStrategy
   :members:


Prompt
======

.. autoclass:: PromptImportStrategy
   :members:
