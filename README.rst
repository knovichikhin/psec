psec
----

|pypi| |coverage|

`psec` is a payment security package for protecting sensitive data
for retail payment transactions and cardholder authentication.

`psec` is built on top of `cryptography <https://pypi.org/project/cryptography/>`_ package.

Also, see `pyemv <https://pypi.org/project/pyemv/>`_ package for EMV security.

Install::

    pip install psec

`psec` modules:

    - cvv - Card Verification Value utilities
    - mac - Message Authentication Code utilities
    - des - Triple DES utilities
    - tools - Miscellaneous tools, such as xor.

Contribute
----------

`psec` is hosted on `GitHub <https://github.com/knovichikhin/psec>`_.

Feel free to fork and send contributions over.

.. |pypi| image:: https://img.shields.io/pypi/v/psec.svg
    :alt: PyPI
    :target:  https://pypi.org/project/psec/

.. |coverage| image:: https://codecov.io/gh/knovichikhin/psec/branch/master/graph/badge.svg
    :alt: Test coverage
    :target: https://codecov.io/gh/knovichikhin/psec
