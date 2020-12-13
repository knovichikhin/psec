r"""PIN blocks are data blocks that contain PIN, pad characters and sometimes
other additional information, such as the leght of the PIN.
"""

from typing import Union
import string as _string
import binascii as _binascii

__all__ = [
    "encode_pin_block_iso9564_2",
    "decode_pin_block_iso9564_2",
]


def encode_pin_block_iso9564_2(pin: Union[bytes, str]) -> bytes:
    r"""Encode ISO 9564 PIN block format 2.
    ISO format 2 PIN block is 8 byte value that consits of

        - Control field. A 4 bit hex value set to 2.
        - PIN length. A 4 bit hex value in the range from 4 to C.
        - PIN digits. Each digit is a 4 bit hex value in the range from 0 to 9.
        - Pad character set to F.

    Parameters
    ----------
    pin : bytes or str
        ASCII Personal Identification Number.

    Returns
    -------
    pin_block : bytes
        Binary 8-byte PIN block.

    Raises
    ------
    ValueError
        PIN must be between 4 and 12 digits long

    Examples
    --------
    >>> from psec.pinblock import encode_pin_block_iso9564_2
    >>> encode_pin_block_iso9564_2("123456789012").hex().upper()
    '2C123456789012FF'
    """
    if len(pin) < 4 or len(pin) > 12:
        raise ValueError("PIN must be between 4 and 12 digits long")

    if isinstance(pin, bytes):
        pin = pin.decode("ascii")

    return (len(pin) + 32).to_bytes(1, "big") + _binascii.a2b_hex(
        pin + "F" * (14 - len(pin))
    )


def decode_pin_block_iso9564_2(pin_block: Union[bytes, str]) -> str:
    r"""Decode ISO 9564 PIN block format 2.
    ISO format 2 PIN block is 8 byte value that consits of

        - Control field. A 4 bit hex value set to 2.
        - PIN length. A 4 bit hex value in the range from 4 to C.
        - PIN digits. Each digit is a 4 bit hex value in the range from 0 to 9.
        - Pad character set to F.

    Parameters
    ----------
    pin_block : bytes or str
        If PIN block is a bytes instance then it's a binary 8-byte PIN block.
        If PIN block is an str instance then it's a hexadecimal 16 character PIN block.

    Returns
    -------
    pin : str
        ASCII Personal Identification Number.

    Raises
    ------
    ValueError
        PIN block must be 8 bytes long
        PIN block must be 16 hexchars long
        PIN block is not ISO format 2: control field `X`
        PIN block filler is incorrect: `filler`
        PIN is not numeric: `pin`

    Examples
    --------
    >>> from psec.pinblock import decode_pin_block_iso9564_2
    >>> decode_pin_block_iso9564_2(bytes.fromhex("2C123456789012FF"))
    '123456789012'
    """

    if isinstance(pin_block, bytes):
        if len(pin_block) != 8:
            raise ValueError("PIN block must be 8 bytes long")
        pin_block = pin_block.hex().upper()
    elif isinstance(pin_block, str):
        if len(pin_block) != 16 or not all(c in _string.hexdigits for c in pin_block):
            raise ValueError("PIN block must be 16 hexchars long")
        pin_block = pin_block.upper()

    if pin_block[0] != "2":
        raise ValueError(
            f"PIN block is not ISO format 2: control field `{pin_block[0]}`"
        )

    pin_len = int(pin_block[1], 16)

    if pin_len < 4 or pin_len > 12:
        raise ValueError(f"PIN length must be between 4 and 12: `{pin_len}`")

    if pin_block[pin_len + 2 :] != ("F" * (14 - pin_len)):
        raise ValueError(f"PIN block filler is incorrect: `{pin_block[pin_len + 2 :]}`")

    pin = pin_block[2 : pin_len + 2]

    if not all(d in _string.digits for d in pin):
        raise ValueError(f"PIN is not numeric: `{pin}`")

    return pin
