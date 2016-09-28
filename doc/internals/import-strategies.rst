
===================
 Import Strategies
===================

.. module:: safe

.. autoexception:: ImportStrategyFailedError
.. autoexception:: ImportStrategyNameConflictError

.. autodata:: import_strategy_map
   :annotation:
.. autofunction:: import_strategy
.. autoclass:: ImportStrategy
   :members:
   :special-members:


Generate
========

.. autodata:: DEFAULT_NEW_SECRET_LENGTH
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
