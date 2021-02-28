r"""psec is a payment security package for protecting sensitive data
for retail payment transactions and cardholder authentication.

psec modules:

    - cvv - Card Verification Value
    - des - Triple DES
    - mac - Message Authentication Code
    - pin - Personal Identification Number
    - pinblock - PIN Blocks encoding and decoding
    - tools - Miscellaneous tools, such as xor.
"""

__version__ = "1.0.1"
__author__ = "Konstantin Novichikhin <konstantin.novichikhin@gmail.com>"

from psec import cvv, des, mac, pin, pinblock, tools
