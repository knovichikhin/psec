r"""psec is a payment security package for protecting sensitive data
for retail payment transactions and cardholder authentication.

psec modules:

    - cvv - Card Verification Value utilities
    - mac - Message Authentication Code utilities
    - des - Triple DES utilities
    - tools - Miscellaneous tools, such as xor.
"""

__version__ = "0.0.0a1"
__author__ = "Konstantin Novichikhin <konstantin.novichikhin@gmail.com>"

from psec import cvv, des, mac, tools
