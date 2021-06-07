from cryptography.hazmat.backends import default_backend as _default_backend
from cryptography.hazmat.primitives.ciphers import Cipher as _Cipher
from cryptography.hazmat.primitives.ciphers import algorithms as _algorithms
from cryptography.hazmat.primitives.ciphers import modes as _modes

__all__ = [
    "encrypt_aes_cbc",
    "encrypt_aes_ecb",
    "decrypt_aes_cbc",
    "decrypt_aes_ecb",
]


def encrypt_aes_cbc(key: bytes, iv: bytes, data: bytes) -> bytes:
    r"""Encrypt data using AES CBC algorithm.

    Parameters
    ----------
    key : bytes
        Binary AES key.
    iv : bytes
        Binary initial initialization vector for CBC.
        Has to be 16 bytes long.
    data : bytes
        Binary data to be encrypted.
        Has to be multiple of 16 bytes.

    Returns
    -------
    encrypted_data : bytes
        Binary encrypted data.

    Raises
    ------
    ValueError

    Examples
    --------
    >>> import psec
    >>> key = bytes.fromhex("0123456789ABCDEFFEDCBA9876543210")
    >>> iv = bytes.fromhex("00000000000000000000000000000000")
    >>> data = bytes.fromhex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF") * 2
    >>> psec.aes.encrypt_aes_cbc(key, iv, data).hex().upper()
    '592373540AE1B202615E6D210D868A8C6593A91B63F201B28860C4DE39375EB4'
    """
    if len(data) < 16 or len(data) % 16 != 0:
        raise ValueError(
            f"Data length ({str(len(data))}) must be multiple of AES block size 16."
        )

    cipher = _Cipher(
        _algorithms.AES(key),
        _modes.CBC(iv),
        backend=_default_backend(),
    )
    return cipher.encryptor().update(data)


def encrypt_aes_ecb(key: bytes, data: bytes) -> bytes:
    r"""Encrypt data using AES ECB algorithm.

    Parameters
    ----------
    key : bytes
        Binary AES key.
    data : bytes
        Binary data to be encrypted.
        Has to be multiple of 16 bytes.

    Returns
    -------
    encrypted_data : bytes
        Binary encrypted data.

    Raises
    ------
    ValueError

    Examples
    --------
    >>> import psec
    >>> key = bytes.fromhex("0123456789ABCDEFFEDCBA9876543210")
    >>> iv = bytes.fromhex("00000000000000000000000000000000")
    >>> data = bytes.fromhex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF") * 2
    >>> psec.aes.encrypt_aes_ecb(key, data).hex().upper()
    '592373540AE1B202615E6D210D868A8C592373540AE1B202615E6D210D868A8C'
    """
    if len(data) < 16 or len(data) % 16 != 0:
        raise ValueError(
            f"Data length ({str(len(data))}) must be multiple of AES block size 16."
        )

    cipher = _Cipher(_algorithms.AES(key), _modes.ECB(), backend=_default_backend())
    return cipher.encryptor().update(data)


def decrypt_aes_cbc(key: bytes, iv: bytes, data: bytes) -> bytes:
    r"""Decrypt data using AES CBC algorithm.

    Parameters
    ----------
    key : bytes
        Binary AES key.
    iv : bytes
        Binary initial initialization vector for CBC.
        Has to be 16 bytes long.
    data : bytes
        Binary data to be decrypted.
        Has to be multiple of 16 bytes.

    Returns
    -------
    decrypted_data : bytes
        Binary decrypted data.

    Raises
    ------
    ValueError

    Examples
    --------
    >>> import psec
    >>> key = bytes.fromhex("0123456789ABCDEFFEDCBA9876543210")
    >>> iv = bytes.fromhex("00000000000000000000000000000000")
    >>> cipher_text = bytes.fromhex("592373540AE1B202615E6D210D868A8C6593A91B63F201B28860C4DE39375EB4")
    >>> psec.aes.decrypt_aes_cbc(key, iv, cipher_text).hex().upper()
    'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF'
    """
    if len(data) < 16 or len(data) % 16 != 0:
        raise ValueError(
            f"Data length ({str(len(data))}) must be multiple of AES block size 16."
        )

    cipher = _Cipher(
        _algorithms.AES(key),
        _modes.CBC(iv),
        backend=_default_backend(),
    )
    return cipher.decryptor().update(data)


def decrypt_aes_ecb(key: bytes, data: bytes) -> bytes:
    r"""Decrypt data using AES ECB algorithm.

    Parameters
    ----------
    key : bytes
        Binary AES key.
    data : bytes
        Binary data to be decrypted.
        Has to be multiple of 16 bytes.

    Returns
    -------
    decrypted_data : bytes
        Binary decrypted data.

    Raises
    ------
    ValueError

    Examples
    --------
    >>> import psec
    >>> key = bytes.fromhex("0123456789ABCDEFFEDCBA9876543210")
    >>> iv = bytes.fromhex("00000000000000000000000000000000")
    >>> cipher_text = bytes.fromhex("592373540AE1B202615E6D210D868A8C6593A91B63F201B28860C4DE39375EB4")
    >>> psec.aes.decrypt_aes_cbc(key, iv, cipher_text).hex().upper()
    'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF'
    """
    if len(data) < 16 or len(data) % 16 != 0:
        raise ValueError(
            f"Data length ({str(len(data))}) must be multiple of AES block size 16."
        )

    cipher = _Cipher(_algorithms.AES(key), _modes.ECB(), backend=_default_backend())
    return cipher.decryptor().update(data)
