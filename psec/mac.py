r"""This module implements ISO/IEC 9797-1 MAC algorithms and
padding methods used in retail payments.

See https://en.wikipedia.org/wiki/ISO/IEC_9797-1 for more information.
"""

from typing import Callable, Dict, Optional

from cryptography.hazmat.backends import default_backend as _default_backend
from cryptography.hazmat.primitives.ciphers import Cipher as _Cipher
from cryptography.hazmat.primitives.ciphers import algorithms as _algorithms
from cryptography.hazmat.primitives.ciphers import modes as _modes

from psec import des as _des

__all__ = [
    "generate_cbc_mac",
    "generate_retail_mac",
    "pad_iso_1",
    "pad_iso_2",
    "pad_iso_3",
]

_pad_dispatch: Dict[int, Callable[[bytes, Optional[int]], bytes]] = {}


def generate_cbc_mac(
    key: bytes, data: bytes, padding: int, length: Optional[int] = None
) -> bytes:
    r"""ISO/IEC 9797-1 MAC algorithm 1 aka CBC MAC.
    All data blocks are processed using TDES CBC.
    The last block is the MAC.

    Parameters
    ----------
    key : bytes
        Binary MAC key. Has to be a valid DES key.
    data : bytes
        Data to be MAC'd.
    padding : int
        Padding method of `data`.

            - 1 = ISO/IEC 9797-1 method 1.
            - 2 = ISO/IEC 9797-1 method 2.
            - 3 = ISO/IEC 9797-1 method 3.

    length : int, optional
        Desired MAC length [4 <= N <= 8] (default 8 bytes).

    Returns
    -------
    mac : bytes
        Returns a binary MAC of requested length

    Raises
    ------
    ValueError
        Invalid padding method specified

    Notes
    -----
    See https://en.wikipedia.org/wiki/ISO/IEC_9797-1 for the
    algorithm reference.

    See Also
    --------
    psec.mac.pad_iso_1 : ISO/IEC 9791-1 padding method 1
    psec.mac.pad_iso_2 : ISO/IEC 9791-1 padding method 2
    psec.mac.pad_iso_3 : ISO/IEC 9791-1 padding method 3

    Examples
    --------
    >>> import psec
    >>> key = bytes.fromhex("0123456789ABCDEFFEDCBA9876543210")
    >>> data = bytes.fromhex("1234567890ABCDEF")
    >>> psec.mac.generate_cbc_mac(key, data, padding=2).hex().upper()
    '925B1737EF681AD3'
    """
    if length is None:
        length = 8

    try:
        data = _pad_dispatch[padding](data, 8)
    except KeyError:
        raise ValueError("Specify valid padding method: 1, 2 or 3.")

    mac = _des.encrypt_tdes_cbc(key, b"\x00\x00\x00\x00\x00\x00\x00\x00", data)[-8:]
    return mac[:length]


def generate_retail_mac(
    key1: bytes, key2: bytes, data: bytes, padding: int, length: Optional[int] = None
) -> bytes:
    r"""ISO/IEC 9797-1 MAC algorithm 3 aka retail MAC.
    Requires two independent keys.
    All blocks until the last are processed using single DES using key1.
    The last data block is processed using TDES using key2 and key1.
    The resulting block is the MAC.

    Parameters
    ----------
    key1 : bytes
        Binary MAC key used in initial transformation.
        Has to be a valid DES key.
    key2 : bytes
        Binary MAC key used  in output transformation.
        Has to be a valid DES key.
    data : bytes
        Data to be MAC'd.
    padding : int
        Padding method of `data`.

            - 1 = ISO/IEC 9797-1 method 1.
            - 2 = ISO/IEC 9797-1 method 2.
            - 3 = ISO/IEC 9797-1 method 3.

    length : int, optional
        Desired MAC length [4 <= N <= 8] (default 8 bytes).

    Returns
    -------
    mac : bytes
        Returns a binary MAC of requested length

    Raises
    ------
    ValueError
        Invalid padding method specified

    Notes
    -----
    See https://en.wikipedia.org/wiki/ISO/IEC_9797-1 for the
    algorithm reference.

    See Also
    --------
    psec.mac.pad_iso_1 : ISO/IEC 9791-1 padding method 1
    psec.mac.pad_iso_2 : ISO/IEC 9791-1 padding method 2
    psec.mac.pad_iso_3 : ISO/IEC 9791-1 padding method 3

    Examples
    --------
    >>> import psec
    >>> key1 = bytes.fromhex("0123456789ABCDEFFEDCBA9876543210")
    >>> key2 = bytes.fromhex("FEDCBA98765432100123456789ABCDEF")
    >>> data = bytes.fromhex("1234567890ABCDEF")
    >>> psec.mac.generate_retail_mac(key1, key2, data, padding=2).hex().upper()
    '644AA5C915DBDAF8'
    """
    if length is None:
        length = 8

    try:
        data = _pad_dispatch[padding](data, 8)
    except KeyError:
        raise ValueError("Specify valid padding method: 1, 2 or 3.")

    # Encrypt first block with key1 then
    # encrypt the rest of the data in CBC mode
    cipher1 = _Cipher(
        _algorithms.TripleDES(key1),
        _modes.CBC(b"\x00\x00\x00\x00\x00\x00\x00\x00"),
        backend=_default_backend(),
    )
    encryptor1 = cipher1.encryptor()
    data = encryptor1.update(data)[-8:]

    # Decrypt the last block with key2 and then encrypt it with key1
    cipher2 = _Cipher(
        _algorithms.TripleDES(key2), _modes.CBC(data), backend=_default_backend()
    )
    decryptor2 = cipher2.decryptor()
    return encryptor1.update(decryptor2.update(data))[:length]


def pad_iso_1(data: bytes, block_size: Optional[int] = None) -> bytes:
    r"""ISO/IEC 9797-1 padding method 1.
    Add the smallest number of "0x00" bytes to the right
    such that the length of resulting message is a multiple of
    `block_size` bytes. If the data is already multiple of
    `block_size` bytes then no bytes added

    Parameters
    ----------
    data : bytes
        Data to be padded
    block_size : int, optional
        Padded data will be multiple of specified block size (default 8).

    Returns
    -------
    bytes
        Padded data

    Notes
    -----
    See https://en.wikipedia.org/wiki/ISO/IEC_9797-1 for the
    algorithm reference.

    Examples
    --------
    >>> import psec
    >>> psec.mac.pad_iso_1(bytes.fromhex("1234")).hex().upper()
    '1234000000000000'
    """
    if block_size is None:
        block_size = 8

    remainder = len(data) % block_size
    if remainder > 0:
        return data + (b"\x00" * (block_size - remainder))

    if len(data) == 0:
        return b"\x00" * block_size

    return data


_pad_dispatch[1] = pad_iso_1


def pad_iso_2(data: bytes, block_size: Optional[int] = None) -> bytes:
    r"""ISO/IEC 9797-1 padding method 2 (equivalent to ISO/IEC 7816-4).
    Add a mandatory "0x80" byte to the right of data,
    and then add the smallest number of "0x00" bytes to the right
    such that the length of resulting message is a multiple of
    `block_size` bytes.

    Parameters
    ----------
    data : bytes
        Data to be padded
    block_size : int, optional
        Padded data will be multiple of specified block size (default 8).

    Returns
    -------
    bytes
        Padded data

    Notes
    -----
    See https://en.wikipedia.org/wiki/ISO/IEC_9797-1 for the
    algorithm reference.

    Examples
    --------
    >>> import psec
    >>> psec.mac.pad_iso_2(bytes.fromhex("1234")).hex().upper()
    '1234800000000000'
    """
    if block_size is None:
        block_size = 8

    return pad_iso_1(data + b"\x80", block_size)


_pad_dispatch[2] = pad_iso_2


def pad_iso_3(data: bytes, block_size: Optional[int] = None) -> bytes:
    r"""ISO/IEC 9797-1 padding method 3.
    The padded data comprises (in this order):
        - The length of the unpadded data (in bits) expressed
          in big-endian binary in `block_size` bits (i.e. one `block_size`)
        - The unpadded data
        - As many (possibly none) bits with value 0 as are required to bring
          the total length to a multiple of `block_size` bits

    Parameters
    ----------
    data : bytes
        Data to be padded
    block_size : int, optional
        Padded data will be multiple of specified block size (default 8).

    Returns
    -------
    bytes
        Padded data

    Notes
    -----
    See https://en.wikipedia.org/wiki/ISO/IEC_9797-1 for the
    algorithm reference.

    Examples
    --------
    >>> import psec
    >>> psec.mac.pad_iso_3(bytes.fromhex("1234")).hex().upper()
    '00000000000000101234000000000000'
    """
    if block_size is None:
        block_size = 8

    return (len(data) * 8).to_bytes(block_size, "big") + pad_iso_1(data, block_size)


_pad_dispatch[3] = pad_iso_3
