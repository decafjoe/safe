
===============
 ``safe.form``
===============

.. automodule:: safe.form

.. autofunction:: slug_validator


``safe.form.account``
=====================

.. automodule:: safe.form.account

.. autofunction:: policy_validator

.. autoclass:: Operation
   :members:

.. autoclass:: AccountForm
   :show-inheritance:
   :members:
   :exclude-members: description, email, question_policy,
                     password_policy, username

   .. autoattribute:: description
      :annotation:

   .. autoattribute:: email
      :annotation:

   .. autoattribute:: question_policy
      :annotation:

   .. autoattribute:: password_policy
      :annotation:

   .. autoattribute:: username
      :annotation:

.. autoclass:: NewAccountForm
   :show-inheritance:
   :members:
   :exclude-members: alias, code, name

   .. autoattribute:: alias
      :annotation:

   .. autoattribute:: code
      :annotation:

   .. autoattribute:: name
      :annotation:

.. autoclass:: UpdateAccountForm
   :show-inheritance:
   :members:
   :exclude-members: alias, code, new_name, question

   .. autoattribute:: alias
      :annotation:

   .. autoattribute:: code
      :annotation:

   .. autoattribute:: new_name
      :annotation:

   .. autoattribute:: question
      :annotation:


``safe.form.policy``
====================

.. automodule:: safe.form.policy

.. autoclass:: PolicyForm
   :show-inheritance:
   :members:
   :exclude-members: description, frequency, generator, length

   .. autoattribute:: description
      :annotation:

   .. autoattribute:: frequency
      :annotation:

   .. autoattribute:: generator
      :annotation:

   .. autoattribute:: length
      :annotation:

.. autoclass:: NewPolicyForm
   :show-inheritance:
   :members:
   :exclude-members: disallowed_characters, name

   .. autoattribute:: disallowed_characters
      :annotation:

   .. autoattribute:: name
      :annotation:

.. autoclass:: UpdatePolicyForm
   :show-inheritance:
   :members:
   :exclude-members: allowed_characters, disallowed_characters, new_name

   .. autoattribute:: allowed_characters
      :annotation:

   .. autoattribute:: disallowed_characters
      :annotation:

   .. autoattribute:: new_name
      :annotation:
