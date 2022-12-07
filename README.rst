|pypi| |coverage|

``psec`` package provides tools for protecting sensitive data and
cardholder authentication in retail payment transactions.

Installation
------------

``psec`` is published on `PyPI`__ and can be installed from there:

.. code-block::

    pip install psec

__ https://pypi.org/project/psec/

Modules
-------

- tr31 - TR-31 key block wrapping and unwrapping
- cvv - Card Verification Value generation
- des - Triple DES utilities (a wrapper over cryptography_)
- aes - AES utilities (a wrapper over cryptography_)
- mac - Message Authentication Code generation
- pin - Personal Identification Number generation
- pinblock - PIN Blocks encoding and decoding

Contributors
------------

- `Konstantin Novichikhin <https://github.com/knovichikhin>`_

  - Author

- `David Schmid <https://github.com/5n00py>`_

  - PIN block ISO 4 support

.. _cryptography:  https://pypi.org/project/cryptography/

.. |pypi| image:: https://img.shields.io/pypi/v/psec.svg
    :alt: PyPI
    :target:  https://pypi.org/project/psec/

.. |coverage| image:: https://codecov.io/gh/knovichikhin/psec/branch/master/graph/badge.svg
    :alt: Test coverage
    :target: https://codecov.io/gh/knovichikhin/psec
