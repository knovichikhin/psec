r"""PIN blocks are data blocks that contain PIN, pad characters and sometimes
other additional information, such as the length of the PIN.
"""

import binascii as _binascii
import secrets as _secrets

from psec import tools as _tools
from psec.aes import encrypt_aes_ecb, decrypt_aes_ecb
from typing import Optional

__all__ = [
    "encode_pinblock_iso_0",
    "encode_pinblock_iso_2",
    "encode_pinblock_iso_3",
    "encode_pin_field_iso_4",
    "encode_pan_field_iso_4",
    "encipher_pinblock_iso_4",
    "decode_pinblock_iso_0",
    "decode_pinblock_iso_2",
    "decode_pinblock_iso_3",
    "decode_pin_field_iso_4",
    "decipher_pinblock_iso_4"
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

    if len(pin) < 4 or len(pin) > 12 or not _tools.ascii_numeric(pin):
        raise ValueError("PIN must be between 4 and 12 digits long")

    if len(pan) < 13 or not _tools.ascii_numeric(pan):
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

    if len(pin) < 4 or len(pin) > 12 or not _tools.ascii_numeric(pin):
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

    if len(pin) < 4 or len(pin) > 12 or not _tools.ascii_numeric(pin):
        raise ValueError("PIN must be between 4 and 12 digits long")

    if len(pan) < 13 or not _tools.ascii_numeric(pan):
        raise ValueError("PAN must be at least 13 digits long")

    random_pad = "".join(_secrets.choice("ABCDEF") for _ in range(10))

    pinblock = (len(pin) + 48).to_bytes(1, "big") + _binascii.a2b_hex(
        pin + random_pad[: 14 - len(pin)]
    )
    pan_block = b"\x00\x00" + _binascii.a2b_hex(pan[-13:-1])

    return _tools.xor(pinblock, pan_block)


def encode_pin_field_iso_4(pin: str, det_pad: Optional[bytes] = None) -> bytes:
    r"""Encode ISO 9564 PIN block format 4 plain text PIN field.
    ISO format 4 PIN plain text PIN field is a 16 byte value that consits of

        - Control field. A 4 bit hex value set to 4.
        - PIN length. A 4 bit hex value in the range from 4 to C.
        - PIN digits. Each digit is a 4 bit hex value in the range from 0 to 9.
        - Fill digits. Each digit is a 4 bit hex value set to A.
        - Random pad character. A 4 bit hex value in the range from 0 to F.

    Parameters
    ----------
    pin :   str
            ASCII Personal Identification Number.
    det_pad (opt) : bytes
                    Optional binary 8-byte deterministic padding to be used instead of random padding
                    supporting deterministic test cases.

    Returns
    -------
    Plain text PIN field : bytes
        Binary 16-byte PIN field block.

    Raises
    ------
    ValueError
        PIN must be between 4 and 12 digits long.
        Padding must be 8 bytes long.

    Examples
    --------
    >>> from psec.pinblock import encode_pin_field_iso_4
    >>> det_pad = bytes.fromhex("548ED7FD65495950")
    >>> encode_pin_field_iso_4("1234", det_pad).hex().upper()
    '441234AAAAAAAAAA548ED7FD65495950'
    """

    if len(pin) < 4 or len(pin) > 12 or not _tools.ascii_numeric(pin):
        raise ValueError("PIN must be between 4 and 12 digits long")

    if det_pad is None:
        random_pad = "".join(_secrets.choice("0123456789ABCDEF") for _ in range(16))
    else:
        if len(det_pad) != 8:
            raise ValueError("Padding must be 8 bytes long.")
        random_pad = det_pad.hex().upper()

    pin_len_hex = len(pin).to_bytes(1, "big").hex()[1]  # Only the low nibble is relevant, values 4 - C.
    pinblock_str = "4" + pin_len_hex + pin + "A" * (14 - len(pin)) + random_pad
    return _binascii.a2b_hex(pinblock_str)


def encode_pan_field_iso_4(pan: str) -> bytes:
    r"""Encode ISO 9564 PIN block format 4 plain text primary account number (PAN) field.
    ISO format 4 plain text primary account number field is a 16 byte value that consits of

        - PAN length. A 4 bit hex value in the range from 0 to 7 indicate a PAN length of 12 plus the value of the field
                      (ranging from dec. 12 to 19). If the PAN is less than 12 digits, the digits are right justified and
                      padded to the left with zeros and PAN length is set to 0.
        - PAN digits. Each digit is a 4 bit hex value in the range from 0 to 9.
        - Pad digits. A 4 bit hex value set to 0.

    Parameters
    ----------
    pan :   str
            ASCII Personal Account Number.

    Returns
    -------
    Plain text PAN field :  bytes
                            Binary 16-byte PAN field.

    Raises
    ------
    ValueError
        PAN must be between 1 and 19 digits long.

    Examples
    --------
    >>> from psec.pinblock import encode_pan_field_iso_4
    >>> encode_pan_field_iso_4("112233445566778899").hex().upper()
    '61122334455667788990000000000000'
    """

    if len(pan) < 1 or len(pan) > 19 or not _tools.ascii_numeric(pan):
        raise ValueError("PAN must be between 1 and 19 digits long.")

    pan_len_field = "0" if len(pan) < 12 else str(len(pan) - 12)

    if len(pan) < 12:
        pan = pan.rjust(12, "0")

    pan_field_str = (pan_len_field + pan).ljust(32, "0")

    return _binascii.a2b_hex(pan_field_str)


def encipher_pinblock_iso_4(key: bytes, pin: str, pan: str, det_pad: Optional[bytes] = None) -> bytes:
    r"""Encrypt PIN with PAN binding according to ISO 9564 PIN block format 4. ISO format 4 is constructed using two
    16-byte fields of PIN and PAN data respecively which are tied in the encryption process resulting in a 16-byte
    enciphered PIN block.

    The following steps are performed:

        - Encode the PIN in the plain text PIN field.
        - Encode the PAN in the plain text primary account number (PAN) field.
        - Encipher the plain text PIN field with key K.
        - Add the resulting intermedate block A modulo-2 (XOR) to the plain text PAN field.
        - Encipher the resulting intermediate block B with the same key K.

    Parameters
    ----------
    key :   bytes
            Binary AES key.
    pin :   str
            ASCII Personal Identification Number.
    pan :   str
            ASCII Personal Account Number.
    det_pad (opt) : bytes
                    Optional binary 8-byte deterministic padding to be used instead of random padding
                    supporting deterministic test cases.

    Returns
    -------
    Enciphered PIN block :  bytes
                            Binary 16-byte enciphered PIN block.

    Raises
    ------
    ValueError
        PIN must be between 4 and 12 digits long
        Padding must be 8 bytes long.
        PAN must be between 1 and 19 digits long.

    Examples
    --------
    >>> from psec.pinblock import encipher_pinblock_iso_4
    >>> key = bytes.fromhex("00112233445566778899AABBCCDDEEFF")
    >>> pin = "1234"
    >>> pan = "1234567890123456"
    >>> det_pad = bytes.fromhex("1122334455667788")
    >>> encipher_pinblock_iso_4(key, pin, pan, det_pad).hex().upper()
    '7CDF645C86CAF763AE34637A66997534'
    """
    pin_field = encode_pin_field_iso_4(pin, det_pad)
    pan_field = encode_pan_field_iso_4(pan)
    intermediate_block_a = encrypt_aes_ecb(key, pin_field)
    intermediate_block_b = _tools.xor(intermediate_block_a, pan_field)
    return encrypt_aes_ecb(key, intermediate_block_b)


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

    if len(pan) < 13 or not _tools.ascii_numeric(pan):
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

    if not _tools.ascii_numeric(pin):
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

    if not _tools.ascii_numeric(pin):
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

    if len(pan) < 13 or not _tools.ascii_numeric(pan):
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

    if not set(block[pin_len + 2 :]).issubset(frozenset("ABCDEF")):
        raise ValueError(f"PIN block filler is incorrect: `{block[pin_len + 2 :]}`")

    pin = block[2 : pin_len + 2]

    if not _tools.ascii_numeric(pin):
        raise ValueError(f"PIN is not numeric: `{pin}`")

    return pin


def decode_pin_field_iso_4(pin_field: bytes) -> str:
    r"""Decode ISO 9564 PIN block format 4 plain text PIN field.
        ISO format 4 PIN plain text PIN field is a 16 byte value that consits of

            - Control field. A 4 bit hex value set to 4.
            - PIN length. A 4 bit hex value in the range from 4 to C.
            - PIN digits. Each digit is a 4 bit hex value in the range from 0 to 9.
            - Fill digits. Each digit is a 4 bit hex value set to A.
            - Random pad character. A 4 bit hex value in the range from 0 to F.

    Parameters
    ----------
    pin_field : bytes
                Binary 16-byte PIN field.

    Returns
    -------
    pin : str
          ASCII Personal Identification Number.

    Raises
    ------
    ValueError
        PIN field must be 16 bytes long
        PIN field must be 32 hexchars long
        PIN field is not ISO format 4: control field `X`
        PIN field filler is incorrect: `filler`
        PIN length must be between 4 and 12: `pin length`
        PIN is not numeric: `pin`

    Examples
    --------
    >>> from psec.pinblock import decode_pin_field_iso_4
    >>> pin_field = bytes.fromhex("441234AAAAAAAAAA548ED7FD65495950")
    >>> decode_pin_field_iso_4(pin_field)
    '1234'
    """

    if len(pin_field) != 16:
        raise ValueError("PIN field must be 16 bytes long")

    pin_field_str = pin_field.hex().upper()

    if pin_field_str[0] != "4":
        raise ValueError(f"PIN block is not ISO format 4: control field `{pin_field_str[0]}`")

    pin_len = int(pin_field_str[1], 16)

    if pin_len < 4 or pin_len > 12:
        raise ValueError(f"PIN length must be between 4 and 12: `{pin_len}`")

    if pin_field_str[pin_len + 2: 16] != ("A" * (14-pin_len)):
        raise ValueError(f"PIN block filler is incorrect: `{pin_field_str[pin_len+2: 16]}`")

    pin = pin_field_str[2: pin_len + 2]

    if not _tools.ascii_numeric(pin):
        raise ValueError(f"PIN is not numeric: `{pin}`")

    return pin


def decipher_pinblock_iso_4(key: bytes, pin_block: bytes, pan: str) -> str:
    r"""Decrypt ISO 9564 PIN block format 4 and extract PIN.

    The following steps are performed:

        - Decipher the PIN block with key K resulting in intermediate block B.
        - Encode the PAN in the plain text primary account number (PAN) field.
        - Add the intermediate block B modulo-2 (XOR) to the plain text PAN field, resulting in intermediate block A.
        - Decipher the intermediate block A with the key K yielding the plain text PIN field.
        - Decode the plain text PIN field and extract the PIN.

    Parameters
    ----------
    key :   bytes
            Binary AES key.
    pin_block : bytes
                Binary 16-byte enciphered PIN block.

    Returns
    -------
    pin :   str
            ASCII Personal Identification Number.

    Raises
    ------
    ValueError
        Data length must be multiple of AES block size 16.
        PAN must be between 1 and 19 digits long.
        PIN block is not ISO format 4: control field `X`
        PIN block filler is incorrect: `filler`
        PIN length must be between 4 and 12: `pin length`"
        PIN is not numeric: `pin`


    Examples
    --------
    >>> from psec.pinblock import decipher_pinblock_iso_4
    >>> key = bytes.fromhex("00112233445566778899AABBCCDDEEFF")
    >>> pan = "1234567890123456"
    >>> pin_block = bytes.fromhex("E4BE5B623AF7E006AC319E5B93544564")
    >>> decipher_pinblock_iso_4(key, pin_block, pan)
    '1234'
    """

    intermediate_block_b = decrypt_aes_ecb(key, pin_block)
    pan_field = encode_pan_field_iso_4(pan)
    intermediate_block_a = _tools.xor(intermediate_block_b, pan_field)
    pin_field = decrypt_aes_ecb(key, intermediate_block_a)
    return decode_pin_field_iso_4(pin_field)
