r"""psec is a payment security package for protecting sensitive data
for retail payment transactions and cardholder authentication.

psec modules:

    - aes - Advanced Encryption Standard
    - cvv - Card Verification Value
    - des - Triple DES
    - mac - Message Authentication Code
    - pin - Personal Identification Number
    - pinblock - PIN Blocks encoding and decoding
    - tools - Miscellaneous tools, such as xor.
    - tr31 - TR-31 key block wrapping and unwrapping
"""

__version__ = "1.1.0"
__author__ = "Konstantin Novichikhin <konstantin.novichikhin@gmail.com>"

from psec import aes, cvv, des, mac, pin, pinblock, tools, tr31
