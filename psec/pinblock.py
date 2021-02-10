r"""PIN blocks are data blocks that contain PIN, pad characters and sometimes
other additional information, such as the leght of the PIN.
"""

import binascii as _binascii
import secrets as _secrets
import string as _string

from psec import tools as _tools

__all__ = [
    "encode_pinblock_iso_0",
    "encode_pinblock_iso_2",
    "encode_pinblock_iso_3",
    "decode_pinblock_iso_0",
    "decode_pinblock_iso_2",
    "decode_pinblock_iso_3",
]


def encode_pinblock_iso_0(pin: str, pan: str) -> bytes:
    r"""Encode ISO 9564 PIN block format 0 aka ANSI PIN block.
    ISO format 0 PIN block is an 8 byte value that consits of

        - Control field. A 4 bit hex value set to 0.
        - PIN length. A 4 bit hex value in the range from 4 to C.
        - PIN digits. Each digit is a 4 bit hex value in the range from 0 to 9.
        - Pad character. A 4 bit hex value set to F.

    The PIN block is then XOR'd by an ANSI PAN block that consists of

        - 4 pad characters. Each is 4 bit hex value set to 0.
        - 12 rightmost digits of the PAN excluding the check digit.

    Parameters
    ----------
    pin : str
        ASCII Personal Identification Number.
    pan : str
        ASCII Personal Account Number.

    Returns
    -------
    pinblock : bytes
        Binary 8-byte PIN block.

    Raises
    ------
    ValueError
        PIN must be between 4 and 12 digits long
        PAN must be at least 13 digits long

    Examples
    --------
    >>> from psec.pinblock import encode_pinblock_iso_0
    >>> encode_pinblock_iso_0("1234", "5544332211009966").hex().upper()
    '041277CDDEEFF669'
    """

    if len(pin) < 4 or len(pin) > 12 or not all(d in _string.digits for d in pin):
        raise ValueError("PIN must be between 4 and 12 digits long")

    if len(pan) < 13 or not all(d in _string.digits for d in pan):
        raise ValueError("PAN must be at least 13 digits long")

    pinblock = len(pin).to_bytes(1, "big") + _binascii.a2b_hex(
        pin + "F" * (14 - len(pin))
    )
    pan_block = b"\x00\x00" + _binascii.a2b_hex(pan[-13:-1])

    return _tools.xor(pinblock, pan_block)


def encode_pinblock_iso_2(pin: str) -> bytes:
    r"""Encode ISO 9564 PIN block format 2.
    ISO format 2 PIN block is an 8 byte value that consits of

        - Control field. A 4 bit hex value set to 2.
        - PIN length. A 4 bit hex value in the range from 4 to C.
        - PIN digits. Each digit is a 4 bit hex value in the range from 0 to 9.
        - Pad character. A 4 bit hex value set to F.

    Parameters
    ----------
    pin : str
        ASCII Personal Identification Number.

    Returns
    -------
    pinblock : bytes
        Binary 8-byte PIN block.

    Raises
    ------
    ValueError
        PIN must be between 4 and 12 digits long

    Examples
    --------
    >>> from psec.pinblock import encode_pinblock_iso_2
    >>> encode_pinblock_iso_2("1234").hex().upper()
    '241234FFFFFFFFFF'
    """

    if len(pin) < 4 or len(pin) > 12 or not all(d in _string.digits for d in pin):
        raise ValueError("PIN must be between 4 and 12 digits long")

    return (len(pin) + 32).to_bytes(1, "big") + _binascii.a2b_hex(
        pin + "F" * (14 - len(pin))
    )


def encode_pinblock_iso_3(pin: str, pan: str) -> bytes:
    r"""Encode ISO 9564 PIN block format 3.
    ISO format 3 PIN block is an 8 byte value that consits of

        - Control field. A 4 bit hex value set to 3.
        - PIN length. A 4 bit hex value in the range from 4 to C.
        - PIN digits. Each digit is a 4 bit hex value in the range from 0 to 9.
        - Random pad character. A 4 bit hex value in the range from A to F.

    The PIN block is then XOR'd by an ANSI PAN block that consists of

        - 4 pad characters. Each is 4 bit hex value set to 0.
        - 12 rightmost digits of the PAN excluding the check digit.

    Parameters
    ----------
    pin : str
        ASCII Personal Identification Number.
    pan : str
        ASCII Personal Account Number.

    Returns
    -------
    pinblock : bytes
        Binary 8-byte PIN block.

    Raises
    ------
    ValueError
        PIN must be between 4 and 12 digits long
        PAN must be at least 13 digits long

    Examples
    --------
    >>> from psec.pinblock import encode_pinblock_iso_3
    >>> encode_pinblock_iso_3("1234", "5544332211009966").hex().upper()[:6]
    '341277'
    """

    if len(pin) < 4 or len(pin) > 12 or not all(d in _string.digits for d in pin):
        raise ValueError("PIN must be between 4 and 12 digits long")

    if len(pan) < 13 or not all(d in _string.digits for d in pan):
        raise ValueError("PAN must be at least 13 digits long")

    random_pad = "".join(_secrets.choice("ABCDEF") for i in range(10))

    pinblock = (len(pin) + 48).to_bytes(1, "big") + _binascii.a2b_hex(
        pin + random_pad[: 14 - len(pin)]
    )
    pan_block = b"\x00\x00" + _binascii.a2b_hex(pan[-13:-1])

    return _tools.xor(pinblock, pan_block)


def decode_pinblock_iso_0(pinblock: bytes, pan: str) -> str:
    r"""Decode ISO 9564 PIN block format 0 aka ANSI PIN block.
    ISO format 0 PIN block is an 8 byte value that consits of

        - Control field. A 4 bit hex value set to 0.
        - PIN length. A 4 bit hex value in the range from 4 to C.
        - PIN digits. Each digit is a 4 bit hex value in the range from 0 to 9.
        - Pad character. A 4 bit hex value set to F.

    The PIN block is then XOR'd by an ANSI PAN block that consists of

        - 4 pad characters. Each is 4 bit hex value set to 0.
        - 12 rightmost digits of the PAN excluding the check digit.

    Parameters
    ----------
    pinblock : bytes
        Binary 8-byte PIN block.
    pan : str
        ASCII Personal Account Number.

    Returns
    -------
    pin : str
        ASCII Personal Identification Number.

    Raises
    ------
    ValueError
        PIN block must be 8 bytes long
        PIN block must be 16 hexchars long
        PIN block is not ISO format 0: control field `X`
        PIN block filler is incorrect: `filler`
        PIN is not numeric: `pin`

    Examples
    --------
    >>> from psec.pinblock import decode_pinblock_iso_0
    >>> decode_pinblock_iso_0(
    ...     bytes.fromhex("041277CDDEEFF669"),
    ...     "5544332211009966")
    '1234'
    """

    if len(pan) < 13 or not all(d in _string.digits for d in pan):
        raise ValueError("PAN must be at least 13 digits long")

    if len(pinblock) != 8:
        raise ValueError("PIN block must be 8 bytes long")

    pan_block = b"\x00\x00" + _binascii.a2b_hex(pan[-13:-1])
    block = _tools.xor(pinblock, pan_block).hex().upper()

    if block[0] != "0":
        raise ValueError(f"PIN block is not ISO format 0: control field `{block[0]}`")

    pin_len = int(block[1], 16)

    if pin_len < 4 or pin_len > 12:
        raise ValueError(f"PIN length must be between 4 and 12: `{pin_len}`")

    if block[pin_len + 2 :] != ("F" * (14 - pin_len)):
        raise ValueError(f"PIN block filler is incorrect: `{block[pin_len + 2 :]}`")

    pin = block[2 : pin_len + 2]

    if not all(d in _string.digits for d in pin):
        raise ValueError(f"PIN is not numeric: `{pin}`")

    return pin


def decode_pinblock_iso_2(pinblock: bytes) -> str:
    r"""Decode ISO 9564 PIN block format 2.
    ISO format 2 PIN block is 8 byte value that consits of

        - Control field. A 4 bit hex value set to 2.
        - PIN length. A 4 bit hex value in the range from 4 to C.
        - PIN digits. Each digit is a 4 bit hex value in the range from 0 to 9.
        - Pad character set to F.

    Parameters
    ----------
    pinblock : bytes
        Binary 8-byte PIN block.

    Returns
    -------
    pin : str
        ASCII Personal Identification Number.

    Raises
    ------
    ValueError
        PIN block must be 8 bytes long
        PIN block is not ISO format 2: control field `X`
        PIN block filler is incorrect: `filler`
        PIN is not numeric: `pin`

    Examples
    --------
    >>> from psec.pinblock import decode_pinblock_iso_2
    >>> decode_pinblock_iso_2(bytes.fromhex("2C123456789012FF"))
    '123456789012'
    """

    if len(pinblock) != 8:
        raise ValueError("PIN block must be 8 bytes long")

    block = pinblock.hex().upper()

    if block[0] != "2":
        raise ValueError(f"PIN block is not ISO format 2: control field `{block[0]}`")

    pin_len = int(block[1], 16)

    if pin_len < 4 or pin_len > 12:
        raise ValueError(f"PIN length must be between 4 and 12: `{pin_len}`")

    if block[pin_len + 2 :] != ("F" * (14 - pin_len)):
        raise ValueError(f"PIN block filler is incorrect: `{block[pin_len + 2 :]}`")

    pin = block[2 : pin_len + 2]

    if not all(d in _string.digits for d in pin):
        raise ValueError(f"PIN is not numeric: `{pin}`")

    return pin


def decode_pinblock_iso_3(pinblock: bytes, pan: str) -> str:
    r"""Decode ISO 9564 PIN block format 3.
    ISO format 3 PIN block is an 8 byte value that consits of

        - Control field. A 4 bit hex value set to 3.
        - PIN length. A 4 bit hex value in the range from 4 to C.
        - PIN digits. Each digit is a 4 bit hex value in the range from 0 to 9.
        - Random pad character. A 4 bit hex value in the range from A to F.

    The PIN block is then XOR'd by an ANSI PAN block that consists of

        - 4 pad characters. Each is 4 bit hex value set to 0.
        - 12 rightmost digits of the PAN excluding the check digit.

    Parameters
    ----------
    pinblock : bytes
        Binary 8-byte PIN block.
    pan : str
        ASCII Personal Account Number.

    Returns
    -------
    pin : str
        ASCII Personal Identification Number.

    Raises
    ------
    ValueError
        PIN block must be 8 bytes long
        PIN block must be 16 hexchars long
        PIN block is not ISO format 3: control field `X`
        PIN block filler is incorrect: `filler`
        PIN is not numeric: `pin`

    Examples
    --------
    >>> from psec.pinblock import decode_pinblock_iso_3
    >>> decode_pinblock_iso_3(
    ...     bytes.fromhex("341277EEEFCCB43C"),
    ...     "5544332211009966")
    '1234'
    """

    if len(pan) < 13 or not all(d in _string.digits for d in pan):
        raise ValueError("PAN must be at least 13 digits long")

    if len(pinblock) != 8:
        raise ValueError("PIN block must be 8 bytes long")

    pan_block = b"\x00\x00" + _binascii.a2b_hex(pan[-13:-1])
    block = _tools.xor(pinblock, pan_block).hex().upper()

    if block[0] != "3":
        raise ValueError(f"PIN block is not ISO format 3: control field `{block[0]}`")

    pin_len = int(block[1], 16)

    if pin_len < 4 or pin_len > 12:
        raise ValueError(f"PIN length must be between 4 and 12: `{pin_len}`")

    if not all(pad in "ABCDEF" for pad in block[pin_len + 2 :]):
        raise ValueError(f"PIN block filler is incorrect: `{block[pin_len + 2 :]}`")

    pin = block[2 : pin_len + 2]

    if not all(d in _string.digits for d in pin):
        raise ValueError(f"PIN is not numeric: `{pin}`")

    return pin
