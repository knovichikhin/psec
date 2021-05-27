import secrets as _secrets
from typing import Dict, Optional, Tuple, Literal

from psec import des as _des
from psec import mac as _mac
from psec import tools as _tools

__all__ = ["generate_key_block_b", "generate_key_block_c"]


class KeyBlock:
    def __init__(self, kbpk: bytes) -> None:
        self.kbpk = kbpk
        self.header: Optional[Header] = None

    def unwrap(self, tr31_key_block: str) -> None:
        pass

    def wrap(self) -> None:
        pass

    def load_header(self, tr31_header: str) -> None:
        pass

    def dump_header(self) -> None:
        pass


class Header:
    _mac_length = {"A": 8, "B": 16, "C": 8, "D": 16}

    _block_size = {
        "A": 8,  # DES
        "B": 8,  # DES
        "C": 8,  # DES
        "D": 16,  # AES
    }

    _valid_key_sizes = {
        "A": {8, 16, 24},
        "B": {16, 24},
        "C": {8, 16, 24},
        "D": {16, 24, 32},
    }

    def __init__(
        self,
        version_id: Literal["A", "B", "C"],
        key_usage: str,
        algorithm: str,
        mode_of_use: str,
        version_num: str,
        exportability: str,
    ) -> None:
        self.version_id = version_id
        self.key_usage = key_usage
        self.algorithm = algorithm
        self.mode_of_use = mode_of_use
        self.version_num = version_num
        self.exportability = exportability
        # self._blocks: Dict[str, str] = {}

    def dump(self, key: bytes, extra_pad: int = 0) -> str:
        """Format TR-31 header"""
        block_size = self._block_size[self.version_id]

        if len(key) not in self._valid_key_sizes[self.version_id]:
            valid_sizes = ", ".join(map(str, self._valid_key_sizes[self.version_id]))
            raise ValueError(
                f"Key must be {valid_sizes} bytes long for key block version {self.version_id}"
            )

        if extra_pad % block_size != 0:
            raise ValueError(
                f"Additional number of random pad bytes must be multiple of {str(block_size)} for key block version {self.version_id}"
            )

        minimum_pad = block_size - ((2 + len(key)) % block_size)

        block_length = (
            16  # mandatory header
            + 4  # key length's length in ASCII
            + (len(key) * 2)  # in ASCII
            + (minimum_pad * 2)  # in ASCII
            + (extra_pad * 2)  # in ASCII
            + self._mac_length[self.version_id]
        )

        if block_length > 9999:
            ValueError("Key block exceeds maximum length of 9999")

        return (
            self.version_id
            + str(block_length).zfill(4)
            + self.key_usage
            + self.algorithm
            + self.mode_of_use
            + self.version_num
            + self.exportability
            + "00"  # Number of optional blocks
            + "00"  # RFU
        )

    """
    def add_block(self, id: str, data: str) -> "Header":
        self._blocks[id] = data
        return self

    def get_block(self, id: str) -> str:
        return self._blocks[id]

    def del_block(self, id: str) -> "Header":
        self._blocks.pop(id)
        return self
    """


def load_key_block(key_block: str) -> KeyBlock:
    return KeyBlock()


#
# Version B: DES key derivation
#


def wrap_b(kbpk: bytes, header: str, key: bytes, extra_pad: int = 0) -> str:
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


def wrap_c(kbpk: bytes, header: str, key: bytes, extra_pad: int = 0) -> str:
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

    kbek = _tools.xor(kbpk, b"\x45" * len(kbpk))  # Key Block Encryption Key
    kbak = _tools.xor(kbpk, b"\x4D" * len(kbpk))  # Key Block Authentication Key
    enc_key = _method_c_encrypt(kbek, header, key, extra_pad)
    mac = _method_c_generate_mac(kbak, header, enc_key)
    return header + enc_key.hex().upper() + mac.hex().upper()


def _method_c_encrypt(kbek: bytes, header: str, key: bytes, extra_pad: int) -> bytes:
    """Encrypt key using KBEK"""
    key_length = (len(key) * 8).to_bytes(2, "big")
    random_data = _secrets.token_bytes(6 + extra_pad)
    return _des.encrypt_tdes_cbc(
        kbek, header.encode("ascii")[:8], key_length + key + random_data
    )


def _method_c_generate_mac(kbak: bytes, header: str, enc_key: bytes) -> bytes:
    """Generate MAC using KBAK"""
    return _mac.generate_cbc_mac(kbak, header.encode("ascii") + enc_key, 1, 4)
