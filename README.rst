|pypi| |coverage|

``psec`` provides tools for protecting sensitive data and
cardholder authentication in retail payment transactions.

Install:

.. code-block::

    pip install psec

``psec`` consists of the following modules:

- cvv - Card Verification Value generation
- des - Triple DES utilities
- mac - Message Authentication Code generation
- pin - Personal Identification Number generation
- pinblock - PIN Blocks encoding and decoding
- tools - Miscellaneous support tools

For example:

.. code-block:: python

    >>> import psec
    >>> psec.pin.generate_visa_pvv(
    ...     pvk = bytes.fromhex("0123456789ABCDEFFEDCBA9876543210"),
    ...     pvki="1",
    ...     pin="1234",
    ...     pan="4321000000001234")
    '6629'

.. |pypi| image:: https://img.shields.io/pypi/v/psec.svg
    :alt: PyPI
    :target:  https://pypi.org/project/psec/

.. |coverage| image:: https://codecov.io/gh/knovichikhin/psec/branch/master/graph/badge.svg
    :alt: Test coverage
    :target: https://codecov.io/gh/knovichikhin/psec
