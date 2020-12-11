from typing import Union

from cryptography.hazmat.backends import default_backend as _default_backend
from cryptography.hazmat.primitives.ciphers import Cipher as _Cipher
from cryptography.hazmat.primitives.ciphers import algorithms as _algorithms
from cryptography.hazmat.primitives.ciphers import modes as _modes

from psec import tools as _tools

__all__ = [
    "adjust_key_parity",
    "key_check_digits",
    "encrypt_tdes_cbc",
    "encrypt_tdes_ecb",
]


def adjust_key_parity(key: Union[bytes, bytearray]) -> bytes:
    r"""Adjust DES key parity key

    Parameters
    ----------
    key : bytes, bytearray
        Binary key to adjust for odd parity.

    Returns
    -------
    adjusted_key : bytes
        Binary key adjusted for odd parity.

    Examples
    --------
    >>> import psec
    >>> key = bytes.fromhex("1A2B3C4D5F0A1B2C4D5F6A7B8C9D0F1A")
    >>> psec.des.adjust_key_parity(key).hex().upper()
    '1A2A3D4C5E0B1A2C4C5E6B7A8C9D0E1A'
    """
    adjusted_key = bytearray(key)

    for i, byte in enumerate(adjusted_key):
        if not _tools.odd_parity(byte):
            adjusted_key[i] ^= 1

    return bytes(adjusted_key)


def key_check_digits(key: bytes, length: int = 2) -> bytes:
    r"""Calculate Triple DES key check digits.

    Parameters
    ----------
    key : bytes
        Binary key to provide check digits for. Has to be a valid DES key.
    length : int, optional
        Number of key check digits bytes provided in the response (default 2).

    Returns
    -------
    check_digits : bytes
        Binary check digits (`length` bytes)

    Examples
    --------
    >>> import psec
    >>> key = bytes.fromhex("0123456789ABCDEFFEDCBA9876543210")
    >>> psec.des.key_check_digits(key).hex().upper()
    '08D7'
    """
    cipher = _Cipher(
        _algorithms.TripleDES(key), _modes.ECB(), backend=_default_backend()
    )
    encryptor = cipher.encryptor()
    return encryptor.update(b"\x00\x00\x00\x00\x00\x00\x00\x00")[:length]


def encrypt_tdes_cbc(key: bytes, iv: bytes, data: bytes) -> bytes:
    r"""Encrypt data using Triple DES CBC algorithm.

    Parameters
    ----------
    key : bytes
        Binary Triple DES key. Has to be a valid DES key.
    iv : bytes
        Binary initial initialization vector for CBC.
    data : bytes
        Binary data to be encrypted.

    Returns
    -------
    encrypted_data : bytes
        Binary encrypted data.

    Examples
    --------
    >>> import psec
    >>> key = bytes.fromhex("0123456789ABCDEFFEDCBA9876543210")
    >>> iv = bytes.fromhex("0000000000000000")
    >>> psec.des.encrypt_tdes_cbc(key, iv, b"12345678").hex().upper()
    '41D2FFBA3CDC15FE'
    """
    cipher = _Cipher(
        _algorithms.TripleDES(key),
        _modes.CBC(iv),
        backend=_default_backend(),
    )
    return cipher.encryptor().update(data)


def encrypt_tdes_ecb(key: bytes, data: bytes) -> bytes:
    r"""Encrypt data using Triple DES ECB algorithm.

    Parameters
    ----------
    key : bytes
        Binary Triple DES key. Has to be a valid DES key.
    data : bytes
        Binary data to be encrypted.

    Returns
    -------
    encrypted_data : bytes
        Binary encrypted data.

    Examples
    --------
    >>> import psec
    >>> key = bytes.fromhex("0123456789ABCDEFFEDCBA9876543210")
    >>> psec.des.encrypt_tdes_ecb(key, b"12345678").hex().upper()
    '41D2FFBA3CDC15FE'
    """
    cipher = _Cipher(
        _algorithms.TripleDES(key), _modes.ECB(), backend=_default_backend()
    )
    return cipher.encryptor().update(data)
