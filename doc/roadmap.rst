
=========
 Roadmap
=========


Bump Default New Secret Length to 128 Characters
================================================

I think this just requires changes to the generate and interactive
strategies. It should probably go into a top-level variable
(``DEFAULT_NEW_SECRET_LENGTH``?) instead of being a bare integer
argument buried inside the import strategy classes.


Make ``GPG_DEFAULT_CIPHER`` a List
==================================

I think this is actually really broken. Scenario: user has a gpg
version without the cast5 cipher. Tries to run safe. Doesn't supply a
``--gpg-cipher`` argument. Safe tries to use cast5. Boom.

The best way to implement this might be to have a short list of
preferred ciphers (aes-es, cast5, blah). If none of those are
available and the user tries to use the gpg backend without specifying
a cipher, safe should error out and tell them that they'll have to
specify the cipher.

Related: this should also make aes256 the default cipher. Once this
change is made, I can update the invocations in my shell environment
(namely, the zsh and ledger repos), removing the
``--gpg-cipher aes256`` option.


Document Reasons for #noqa
==========================

For every #noqa instance, it should note the error it's overriding and
the reason for the override.


Add Tests for Echo Command
==========================

The echo command was hacked in as a quick necessity to get the ball
rolling with safe. It should actually have tests.


Finish Module Documentation
===========================

Namely, inside ``safe.py``. At this point, I've gotten through the
ImportStrategy base class. The rest of the module needs done in the
same style.


Make Tests PEP257-Compliant
===========================

This is a large project, and must be done incrementally so I stay
sane. Run ``make lint-pep257`` to run coverage with all the 257 checks
enabled. Reduce the number of failures. Quit when it gets maddening.
Repeat a few days later.

Once everything is compliant, I can make the ``lint-pep257`` target
the default lint target.


Add Tests to Documentation
==========================

Why not? If I'm going to write all those fucking docstrings, I might
has well present them nicely. This can be done in parallel with the
PEP257-compliance item.


Figure Out What's Up with Coverage
==================================

Right now, the yield statements are getting marked as uncovered.
However, the tests would fail if they weren't actually getting hit.
Not sure why this is, have a feeling it might be fixed in an updated
version of coverage before I actually get to looking into this.
