import secrets as _secrets
from typing import Callable, Dict, Optional, Tuple, Literal

from psec import des as _des
from psec import mac as _mac
from psec import tools as _tools

__all__ = ["wrap_b", "wrap_c", "unwrap_b", "unwrap_c", "KeyBlock", "Header"]


_ascii_alphanumeric = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
_ascii_digit = "0123456789"


def _is_ascii_alphanumeric(s: str) -> bool:
    return all(c in _ascii_alphanumeric for c in s)


def _is_ascii_numeric(s: str) -> bool:
    return all(c in _ascii_digit for c in s)


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
    >>> psec.tr31.wrap_b(
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


def unwrap_b(kbpk: bytes, header: str, key_and_mac: str) -> bytes:

    if len(kbpk) not in (16, 24):
        raise ValueError("KBPK must be a double or triple DES key")

    if len(header) < 16:
        raise ValueError("Key block header must be at a minimum 16 characters long")

    if len(header) % 8 != 0:
        raise ValueError("Key block header length must be multiple of 8")

    try:
        received_mac = bytes.fromhex(key_and_mac[-16:])
    except ValueError:
        raise ValueError(f"Key block MAC is invalid: '{key_and_mac[-16:]}'")

    if len(received_mac) != 8:
        raise ValueError(f"Key block MAC length must be 16: '{key_and_mac[-16:]}'")

    try:
        enc_key = bytes.fromhex(key_and_mac[:-16])
    except ValueError:
        raise ValueError(f"Encrypted key is invalid: '{key_and_mac[-16:]}'")

    if len(enc_key) < 8 or len(enc_key) % 8 != 0:
        raise ValueError(
            f"Encrypted key length must be multiple of 8: '{key_and_mac[-16:]}'"
        )

    kbek, kbak = _method_b_derive(kbpk)
    key, pad = _method_b_decrypt(kbek, enc_key, received_mac)
    mac = _method_b_generate_mac(kbak, header, key, pad)
    if mac != received_mac:
        raise ValueError(f"Key block MAC does not match: '{mac.hex().upper()}'")

    return key


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


def _method_b_decrypt(kbek: bytes, key: bytes, mac: bytes) -> Tuple[bytes, bytes]:
    """Decrypt key using KBEK. Return decrypted key and pad."""
    key_data = _des.decrypt_tdes_cbc(kbek, mac, key)

    key_length = int.from_bytes(key_data[0:2], "big", signed=False)
    if key_length < 64 or key_length % 64 != 0:
        raise ValueError(f"Decrypted key length is invalid: '{str(key_length)}'")

    key = key_data[2 : (key_length // 8) + 2]
    if len(key) != key_length // 8:
        raise ValueError(f"Decrypted key length is invalid: '{key.hex().upper()}'")

    return key, key_data[len(key) + 2 :]


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
# Version A and C: DES variant
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
    >>> psec.tr31.wrap_c(
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


class Header:
    _mac_length = {"A": 8, "B": 16, "C": 8, "D": 32}

    _block_size = {"A": 8, "B": 8, "C": 8, "D": 16}

    _valid_key_sizes = {
        "A": {8, 16, 24},
        "B": {16, 24},
        "C": {8, 16, 24},
        "D": {16, 24, 32},
    }

    def __init__(
        self,
        version_id: Literal["A", "B", "C", "D"] = "B",
        key_usage: str = "00",
        algorithm: str = "0",
        mode_of_use: str = "0",
        version_num: str = "00",
        exportability: str = "0",
        reserved: str = "00",
        block_length: str = "0000",
    ) -> None:
        self.version_id = version_id
        self.block_length = block_length
        self.key_usage = key_usage
        self.algorithm = algorithm
        self.mode_of_use = mode_of_use
        self.version_num = version_num
        self.exportability = exportability
        self.reserved = reserved

    def __str__(self) -> str:
        return (
            self.version_id
            + self.block_length
            + self.key_usage
            + self.algorithm
            + self.mode_of_use
            + self.version_num
            + self.exportability
            + "00"  # Number of optional blocks
            + self.reserved
        )

    @property
    def version_id(self) -> str:
        return self._version_id

    @version_id.setter
    def version_id(self, version_id: Literal["A", "B", "C", "D"]) -> None:
        if version_id not in ("A", "B", "C", "D"):
            raise ValueError(f"Version ID is not supported: '{version_id}'")
        self._version_id = version_id

    @property
    def block_length(self) -> str:
        return self._block_length

    @block_length.setter
    def block_length(self, block_length: str) -> None:
        if len(block_length) != 4 or not _is_ascii_numeric(block_length):
            raise ValueError(f"Block length is invalid: '{block_length}'")
        self._block_length = block_length

    @property
    def key_usage(self) -> str:
        return self._key_usage

    @key_usage.setter
    def key_usage(self, key_usage: str) -> None:
        if len(key_usage) != 2 or not _is_ascii_alphanumeric(key_usage):
            raise ValueError(f"Key Usage is invalid: '{key_usage}'")
        self._key_usage = key_usage

    @property
    def algorithm(self) -> str:
        return self._algorithm

    @algorithm.setter
    def algorithm(self, algorithm: str) -> None:
        if len(algorithm) != 1 or not _is_ascii_alphanumeric(algorithm):
            raise ValueError(f"Algorithm is invalid: '{algorithm}'")
        self._algorithm = algorithm

    @property
    def mode_of_use(self) -> str:
        return self._mode_of_use

    @mode_of_use.setter
    def mode_of_use(self, mode_of_use: str) -> None:
        if len(mode_of_use) != 1 or not _is_ascii_alphanumeric(mode_of_use):
            raise ValueError(f"Mode of use is invalid: '{mode_of_use}'")
        self._mode_of_use = mode_of_use

    @property
    def version_num(self) -> str:
        return self._version_num

    @version_num.setter
    def version_num(self, version_num: str) -> None:
        if len(version_num) != 2 or not _is_ascii_alphanumeric(version_num):
            raise ValueError(f"Version number is invalid: '{version_num}'")
        self._version_num = version_num

    @property
    def exportability(self) -> str:
        return self._exportability

    @exportability.setter
    def exportability(self, exportability: str) -> None:
        if len(exportability) != 1 or not _is_ascii_alphanumeric(exportability):
            raise ValueError(f"Exportability is invalid: '{exportability}'")
        self._exportability = exportability

    @property
    def reserved(self) -> str:
        return self._reserved

    @reserved.setter
    def reserved(self, reserved: str) -> None:
        if len(reserved) != 2 or not _is_ascii_alphanumeric(reserved):
            raise ValueError(f"Reserved field is invalid: '{reserved}'")
        self._reserved = reserved

    def dump(self, key_length: int, extra_pad: int = 0) -> str:
        """Format TR-31 header into string"""

        if key_length not in self._valid_key_sizes[self.version_id]:
            valid_sizes = ", ".join(map(str, self._valid_key_sizes[self.version_id]))
            raise ValueError(
                f"Key must be {valid_sizes} bytes long for key block version {self.version_id}"
            )

        block_size = self._block_size[self.version_id]
        if extra_pad % block_size != 0:
            raise ValueError(
                f"Additional number of random pad bytes must be multiple of {str(block_size)} for key block version {self.version_id}"
            )

        minimum_pad = block_size - ((2 + key_length) % block_size)

        block_length = (
            16  # mandatory header
            + 4  # key length's length in ASCII
            + (key_length * 2)  # in ASCII
            + (minimum_pad * 2)  # in ASCII
            + (extra_pad * 2)  # in ASCII
            + self._mac_length[self.version_id]
        )

        if block_length > 9992:
            ValueError(f"Key block length {str(block_length)} exceeds maximum of 9992")

        return (
            self.version_id
            + str(block_length).zfill(4)
            + self.key_usage
            + self.algorithm
            + self.mode_of_use
            + self.version_num
            + self.exportability
            + "00"  # Number of optional blocks
            + self.reserved
        )

    def load(self, header: str) -> int:
        """Load TR-31 header from string"""

        if not _is_ascii_alphanumeric(header):
            raise ValueError("Header must be ASCII alphanumeric")

        if len(header) % 8 != 0:
            raise ValueError("Header must be multiple of 8")

        if len(header) < 16:
            raise ValueError("Header must be at a minimum 16 characters long")

        self.version_id = header[0]
        self.block_length = header[1:5]
        self.key_usage = header[5:7]
        self.algorithm = header[7]
        self.mode_of_use = header[8]
        self.version_num = header[9:11]
        self.exportability = header[11]
        self.reserved = header[14:16]

        return 16


class KeyBlock:
    _wrap_dispatch: Dict[str, Callable[[bytes, str, bytes, int], str]] = {
        "A": wrap_c,
        "B": wrap_b,
        "C": wrap_c,
    }

    _unwrap_dispatch: Dict[str, Callable[[bytes, str, str], bytes]] = {
        "A": unwrap_b,
        "B": unwrap_b,
        "C": unwrap_b,
    }

    def __init__(self, kbpk: bytes, header: Optional[Header] = None) -> None:
        self.kbpk = kbpk
        self.header = header or Header()

    def unwrap(self, key_block: str) -> bytes:
        if not _is_ascii_alphanumeric(key_block):
            raise ValueError("Key block must be ASCII alphanumeric")

        if len(key_block) % 8 != 0:
            raise ValueError("Key block must be multiple of 8")

        try:
            key_block_length = int(key_block[1:5])
        except ValueError:
            raise ValueError(f"Key block length is invalid: '{key_block[1:5]}'")

        if key_block_length != len(key_block):
            raise ValueError(
                f"Key block length '{key_block[1:5]}' doesn't match data length {str(key_block_length)}"
            )

        header_length = self.header.load(key_block)

        try:
            unwrap = self._unwrap_dispatch[self.header.version_id]
        except KeyError:
            raise ValueError(
                f"Key block version ID is not supported: '{self.header.version_id}'"
            )

        return unwrap(self.kbpk, key_block[:header_length], key_block[header_length:])

    def wrap(self, key: bytes, extra_pad: int = 0) -> str:
        try:
            wrap = self._wrap_dispatch[self.header.version_id]
        except KeyError:
            raise ValueError(
                f"Key block version ID is not supported: '{self.header.version_id}'"
            )

        return wrap(self.kbpk, self.header.dump(len(key), extra_pad), key, extra_pad)
