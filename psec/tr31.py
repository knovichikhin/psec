import secrets as _secrets
from typing import Tuple

from psec import des as _des
from psec import mac as _mac
from psec import tools as _tools

__all__ = ["generate_key_block_a", "generate_key_block_b"]

#
# Version B: DES key derivation
#


def generate_key_block_b(
    kbpk: bytes, header: str, key: bytes, extra_pad: int = 0
) -> str:
    """Generate TR-31 key block version B.

    Parameters
    ----------
    kbpk : bytes
        Key Block Protection Key.
        The length of the KBPK must equal or greater
        than the key to be protected.
        Must be a valid DES key.
    header : str
        TR-31 key block header.
        This function does not validate the contents
        of the header. It will check that the header
        fullfils minimum length requirement and
        is multiple of 8 bytes.
    key : bytes
        DES key to be protected.
    extra_pad : int
        Add a number of extra bytes of random data to
        the key to mask true key length.
        Must be multiple of 8. Default 0.
        For example, to make double DES key appear as
        a triple DES set extra_pad to 8.

    Returns
    -------
    tr31_key_block : str
        Key formatted in a TR-31 key block and encrypted
        under the KBPK.

    Raises
    ------
    ValueError
        KBPK must be a double or triple DES key
        Key block header must be at a minimum 16 characters long
        Key block header length must be multiple of 8
        Key must be a double or triple DES key
        Key must not be longer than KBPK
        Additional number of random pad bytes must be multiple of 8

    Notes
    -----
    TR-31 version C is identical to version A with exception
    of some of the key headers values that have been clarified.

    Examples
    --------
    >>> import psec
    >>> psec.tr31.generate_key_block_b(
    ...     kbpk = bytes.fromhex("11111111111111112222222222222222"),
    ...     header = "B0080P0TE00E0000",
    ...     key = bytes.fromhex("33333333333333334444444444444444"))  # doctest: +SKIP
    'B0080P0TE00E0000809A8F0866A01A5A717900602BE435161A24128E75338A2B3AC48A831ABFCEE5'
    """

    if len(kbpk) not in (16, 24):
        raise ValueError("KBPK must be a double or triple DES key")

    if len(header) < 16:
        raise ValueError("Key block header must be at a minimum 16 characters long")

    if len(header) % 8 != 0:
        raise ValueError("Key block header length must be multiple of 8")

    if len(key) not in (16, 24):
        raise ValueError("Key must be a double or triple DES key")

    if len(key) > len(kbpk):
        raise ValueError("Key must not be longer than KBPK")

    if extra_pad % 8 != 0:
        raise ValueError("Additional number of random pad bytes must be multiple of 8")

    kbek, kbak = _method_b_derive(kbpk)
    pad = _secrets.token_bytes(6 + extra_pad)
    pad = b"\x30\x11\x1D\x18\xCC\x4C"
    mac = _method_b_generate_mac(kbak, header, key, pad)
    enc_key = _method_b_encrypt(kbek, key, mac, pad)
    return header + enc_key.hex().upper() + mac.hex().upper()


def _method_b_derive(kbpk: bytes) -> Tuple[bytes, bytes]:
    """Derive Key Block Encryption and Authentication Keys"""

    if len(kbpk) == 16:
        # 2-key DES
        algo = b"\x00\x00"
        key_length = b"\00\x80"
    else:
        # 3-key DES
        algo = b"\x00\x01"
        key_length = b"\00\xC0"

    kbek = bytearray()  # encryption key
    kbak = bytearray()  # authentication key
    k1, _ = _derive_cmac_subkey_des(kbpk)

    for i in range(1, len(kbpk) // 8 + 1):
        # Counter is incremented for each 8 byte block
        counter = i.to_bytes(1, "big")
        kbek += _mac.generate_cbc_mac(
            kbpk,
            _tools.xor(
                counter
                + b"\x00\x00"  # Encryption key
                + b"\x00"  # Mandatory separator
                + algo
                + key_length,
                k1,
            ),
            1,
        )
        kbak += _mac.generate_cbc_mac(
            kbpk,
            _tools.xor(
                counter
                + b"\x00\x01"  # Authentication key
                + b"\x00"  # Mandatory separator
                + algo
                + key_length,
                k1,
            ),
            1,
        )

    return bytes(kbek), bytes(kbak)


def _method_b_encrypt(kbek: bytes, key: bytes, mac: bytes, pad: bytes) -> bytes:
    """Encrypt key using KBEK"""
    key_length = (len(key) * 8).to_bytes(2, "big")
    return _des.encrypt_tdes_cbc(kbek, mac, key_length + key + pad)


def _method_b_generate_mac(kbak: bytes, header: str, key: bytes, pad: bytes) -> bytes:
    """Generate MAC using KBAK"""
    km1, _ = _derive_cmac_subkey_des(kbak)
    binary_data = header.encode("ascii") + (len(key) * 8).to_bytes(2, "big") + key + pad
    binary_data = binary_data[:-8] + _tools.xor(binary_data[-8:], km1)
    mac = _mac.generate_cbc_mac(kbak, binary_data, 1)
    return mac


def _derive_cmac_subkey_des(key: bytes) -> Tuple[bytes, bytes]:
    """Derive two subkeys from a DES key. Each subkey is 8 bytes."""

    def _shift_left_by_1(in_bytes: bytes) -> bytes:
        """Shift byte array left by 1 bit"""
        out_bytes = bytearray()
        out_bytes += ((in_bytes[0] & 0b01111111) << 1).to_bytes(1, "big")
        for i in range(1, len(in_bytes)):
            if in_bytes[i] & 0b10000000:
                out_bytes[i - 1] = out_bytes[i - 1] | 0b00000001
            out_bytes += ((in_bytes[i] & 0b01111111) << 1).to_bytes(1, "big")

        return bytes(out_bytes)

    r64 = b"\x00\x00\x00\x00\x00\x00\x00\x1B"

    s = _des.encrypt_tdes_ecb(key, b"\x00" * 8)

    if s[0] & 0b10000000:
        k1 = _tools.xor(_shift_left_by_1(s), r64)
    else:
        k1 = _shift_left_by_1(s)

    if k1[0] & 0b10000000:
        k2 = _tools.xor(_shift_left_by_1(k1), r64)
    else:
        k2 = _shift_left_by_1(k1)

    return k1, k2


#
# Version A and C: variant
#


def generate_key_block_a(
    kbpk: bytes, header: str, key: bytes, extra_pad: int = 0
) -> str:
    """Generate TR-31 key block version A or C.

    Parameters
    ----------
    kbpk : bytes
        Key Block Protection Key.
        The length of the KBPK must equal or greater
        than the key to be protected.
        Must be a valid DES key.
    header : str
        TR-31 key block header.
        This function does not validate the contents
        of the header. It will check that the header
        fullfils minimum length requirement and
        is multiple of 8 bytes.
    key : bytes
        DES key to be protected.
    extra_pad : int
        Add a number of extra bytes of random data to
        the key to mask true key length.
        Must be multiple of 8. Default 0.
        For example, to make double DES key appear as
        a triple DES set extra_pad to 8.

    Returns
    -------
    tr31_key_block : str
        Key formatted in a TR-31 key block and encrypted
        under the KBPK.

    Raises
    ------
    ValueError
        KBPK must be a single, double or triple DES key
        Key block header must be at a minimum 16 characters long
        Key block header length must be multiple of 8
        Key must be a single, double or triple DES key
        Key must not be longer than KBPK
        Additional number of random pad bytes must be multiple of 8

    Notes
    -----
    TR-31 version C is identical to version A with exception
    of some of the key headers values that have been clarified.

    Examples
    --------
    >>> import psec
    >>> psec.tr31.generate_key_block_a(
    ...     kbpk = bytes.fromhex("11111111111111112222222222222222"),
    ...     header = "A0072P0TE00E0000",
    ...     key = bytes.fromhex("33333333333333334444444444444444"))  # doctest: +SKIP
    'A0072P0TE00E0000C05F5CD188E4CA22D6E8B28C182E87F6907F4569CB3624C336A33E1E'
    """

    if len(kbpk) not in (8, 16, 24):
        raise ValueError("KBPK must be a single, double or triple DES key")

    if len(header) < 16:
        raise ValueError("Key block header must be at a minimum 16 characters long")

    if len(header) % 8 != 0:
        raise ValueError("Key block header length must be multiple of 8")

    if len(key) not in (8, 16, 24):
        raise ValueError("Key must be a single, double or triple DES key")

    if len(key) > len(kbpk):
        raise ValueError("Key must not be longer than KBPK")

    if extra_pad % 8 != 0:
        raise ValueError("Additional number of random pad bytes must be multiple of 8")

    kbek, kbak = _method_a_derive(kbpk)
    enc_key = _method_a_encrypt(kbek, header, key, extra_pad)
    mac = _method_a_generate_mac(kbak, header, enc_key)
    return header + enc_key.hex().upper() + mac.hex().upper()


def _method_a_derive(kbpk: bytes) -> Tuple[bytes, bytes]:
    """Derive Key Block Encryption and Authentication Keys"""
    kbek = _tools.xor(kbpk, b"\x45" * len(kbpk))
    kbak = _tools.xor(kbpk, b"\x4D" * len(kbpk))
    return (kbek, kbak)


def _method_a_encrypt(kbek: bytes, header: str, key: bytes, extra_pad: int) -> bytes:
    """Encrypt key using KBEK"""
    key_length = (len(key) * 8).to_bytes(2, "big")
    random_data = _secrets.token_bytes(6 + extra_pad)
    return _des.encrypt_tdes_cbc(
        kbek, header.encode("ascii")[:8], key_length + key + random_data
    )


def _method_a_generate_mac(kbak: bytes, header: str, enc_key: bytes) -> bytes:
    """Generate MAC using KBAK"""
    return _mac.generate_cbc_mac(kbak, header.encode("ascii") + enc_key, 1, 4)
