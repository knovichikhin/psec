import secrets as _secrets
from typing import Optional, Tuple

from psec import des as _des
from psec import mac as _mac
from psec import tools as _tools


def generate_key_block_b(
    kbpk: bytes,
    header: str,
    key: bytes,
    mask_key_length: Optional[int] = None,
    debug_static_pad: Optional[bytes] = None,
) -> str:
    kbek, kbak = _method_b_derive(kbpk)

    if debug_static_pad is None:
        if mask_key_length is None:
            mask_key_length = 0
        pad = _secrets.token_bytes(6 + mask_key_length)
    else:
        pad = debug_static_pad

    mac = _method_b_generate_mac(kbak, header, key, pad)
    enc_key = _method_b_encrypt(kbek, key, mac, pad)
    return header + enc_key.hex().upper() + mac.hex().upper()


def _method_b_derive(kbpk: bytes) -> Tuple[bytes, bytes]:
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
    k1, _ = _derive_subkey_tdes(kbpk)

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


def _derive_subkey_tdes(key: bytes) -> Tuple[bytes, bytes]:
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


def _shift_left_by_1(bytes_sequence: bytes) -> bytes:
    out = bytearray()
    out += ((bytes_sequence[0] & 0b01111111) << 1).to_bytes(1, "big")
    for i in range(1, len(bytes_sequence)):
        if bytes_sequence[i] & 0b10000000:
            out[i - 1] = out[i - 1] | 0b00000001
        out += ((bytes_sequence[i] & 0b01111111) << 1).to_bytes(1, "big")

    return bytes(out)


def _method_b_encrypt(
    kbek: bytes,
    key: bytes,
    mac: bytes,
    pad: bytes,
) -> bytes:
    key_length = (len(key) * 8).to_bytes(2, "big")
    return _des.encrypt_tdes_cbc(kbek, mac, key_length + key + pad)

def _method_b_generate_mac(kbak: bytes, header: str, key: bytes,
    pad: bytes,) -> bytes:
    """Generate MAC over header and encrypted key"""
    km1, _ = _derive_subkey_tdes(kbak)
    binary_data = header.encode("ascii") + (len(key) * 8).to_bytes(2, "big") + key + pad
    binary_data = binary_data[:-8] + _tools.xor(binary_data[-8:], km1)
    mac = _mac.generate_cbc_mac(kbak, binary_data, 1)
    return mac


#
# Variant
#


def generate_key_block_a(
    kbpk: bytes,
    header: str,
    key: bytes,
    mask_key_length: Optional[int] = None,
    debug_static_pad: Optional[bytes] = None,
) -> str:
    kbek, kbak = _method_a_derive(kbpk)
    enc_key = _method_a_encrypt(
        kbek,
        header,
        key,
        extra_pad=mask_key_length,
        random_data=debug_static_pad,
    )
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
    extra_pad: Optional[int] = None,
    random_data: Optional[bytes] = None,
) -> bytes:
    """Encrypt DES key data
    extra_pad - must be multiple of 8. Add extra length to hide actual key length
    """

    key_length = (len(key) * 8).to_bytes(2, "big")
    if random_data is None:
        if extra_pad is None:
            extra_pad = 0
        random_data = _secrets.token_bytes(6 + extra_pad)

    return _des.encrypt_tdes_cbc(
        kbek, header.encode("ascii")[:8], key_length + key + random_data
    )


def _method_a_generate_mac(kbak: bytes, header: str, enc_key: bytes) -> bytes:
    """Generate MAC over header and encrypted key"""
    mac = _mac.generate_cbc_mac(kbak, header.encode("ascii") + enc_key, 1, 4)
    return mac
