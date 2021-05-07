import secrets as _secrets
from typing import Optional, Tuple

from psec import des as _des
from psec import mac as _mac
from psec import tools as _tools


def _derive_tdes_keys_cmac(kbpk: bytes) -> Tuple[bytes, bytes]:
    """Derive Key Block Encryption and Authentication Keys using CMAC.
    This key derivation method is used in TR31 option B."""

    # The only supported options are double and triple DES keys
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

    for i in range(1, len(kbpk) // 8 + 1):
        # Counter is incremented for each 8 byte block
        counter = i.to_bytes(1, "big")
        kbek += _mac.generate_cbc_mac(
            kbpk,
            counter
            + b"\x00\x00"  # Encryption key
            + b"\x00"  # Mandatory separator
            + algo
            + key_length,
            1,
        )
        kbak += _mac.generate_cbc_mac(
            kbpk,
            counter
            + b"\x00\x01"  # Authentication key
            + b"\x00"  # Mandatory separator
            + algo
            + key_length,
            1,
        )

    return bytes(kbek), bytes(kbak)


#
# Variant
#


def generate_key_block_a(
    kbpk: bytes,
    header: str,
    key: bytes,
    mask_key_length: Optional[int] = None,
    debug_static_random_data: Optional[bytes] = None,
) -> str:
    kbek, kbak = _method_a_derive(kbpk)
    enc_key = _method_a_encrypt(kbek, header, key, random_data=debug_static_random_data)
    mac = _method_a_generate_mac(kbak, header, enc_key)
    return header + enc_key.hex().upper() + mac.hex().upper()


def _method_a_derive(kbpk: bytes) -> Tuple[bytes, bytes]:
    kbek = _tools.xor(kbpk, b"\x45" * len(kbpk))
    kbak = _tools.xor(kbpk, b"\x4D" * len(kbpk))
    return (kbek, kbak)


def _method_a_encrypt(
    kbek: bytes,
    header: str,
    key: bytes,
    extra_pad: int = 0,
    random_data: Optional[bytes] = None,
) -> bytes:
    """Encrypt DES key data
    extra_pad - must be multiple of 8. Add extra length to hide actual key length
    """

    key_length = (len(key) * 8).to_bytes(2, "big")
    if random_data is None:
        random_data = _secrets.token_bytes(6 + extra_pad)

    return _des.encrypt_tdes_cbc(
        kbek, header.encode("ascii")[:8], key_length + key + random_data
    )


def _method_a_generate_mac(kbak: bytes, header: str, enc_key: bytes) -> bytes:
    """Generate MAC over header and encrypted key"""
    mac = _mac.generate_cbc_mac(kbak, header.encode("ascii") + enc_key, 1, 4)
    return mac
