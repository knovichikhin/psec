import secrets as _secrets
from typing import Callable, Dict, Optional, Tuple

from psec import des as _des
from psec import mac as _mac
from psec import tools as _tools

__all__ = ["wrap", "unwrap", "KeyBlock", "Header"]

# Version B


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
        raise ValueError(f"Extra pad must be multiple of 8: {str(extra_pad)}")

    kbek, kbak = _b_derive(kbpk)
    pad = _secrets.token_bytes(6 + extra_pad)
    mac = _b_generate_mac(kbak, header, key, pad)
    enc_key = _b_encrypt(kbek, key, mac, pad)
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

    kbek, kbak = _b_derive(kbpk)
    key, pad = _b_decrypt(kbek, enc_key, received_mac)
    mac = _b_generate_mac(kbak, header, key, pad)
    if mac != received_mac:
        raise ValueError(f"Key block MAC does not match: '{mac.hex().upper()}'")

    return key


def _b_derive(kbpk: bytes) -> Tuple[bytes, bytes]:
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
    k1, _ = _derive_tdes_cmac_subkey(kbpk)

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


def _b_encrypt(kbek: bytes, key: bytes, mac: bytes, pad: bytes) -> bytes:
    """Encrypt key using KBEK"""
    key_length = (len(key) * 8).to_bytes(2, "big")
    return _des.encrypt_tdes_cbc(kbek, mac, key_length + key + pad)


def _b_decrypt(kbek: bytes, enc_key: bytes, mac: bytes) -> Tuple[bytes, bytes]:
    """Decrypt key using KBEK. Return decrypted key and pad."""
    key_data = _des.decrypt_tdes_cbc(kbek, mac, enc_key)

    key_length = int.from_bytes(key_data[0:2], "big")
    if key_length < 64 or key_length % 64 != 0:
        raise ValueError(f"Decrypted key length is invalid: '{str(key_length)}'")

    key = key_data[2 : (key_length // 8) + 2]
    if len(key) != key_length // 8:
        raise ValueError(f"Decrypted key length is invalid: '{key.hex().upper()}'")

    return key, key_data[len(key) + 2 :]


def _b_generate_mac(kbak: bytes, header: str, key: bytes, pad: bytes) -> bytes:
    """Generate MAC using KBAK"""
    km1, _ = _derive_tdes_cmac_subkey(kbak)
    binary_data = header.encode("ascii") + (len(key) * 8).to_bytes(2, "big") + key + pad
    binary_data = binary_data[:-8] + _tools.xor(binary_data[-8:], km1)
    mac = _mac.generate_cbc_mac(kbak, binary_data, 1)
    return mac


def _derive_tdes_cmac_subkey(key: bytes) -> Tuple[bytes, bytes]:
    """Derive two subkeys from a DES key. Each subkey is 8 bytes."""

    def _shift_left_by_1(in_bytes: bytes) -> bytes:
        """Shift byte array left by 1 bit"""
        in_bytes = bytearray(in_bytes)
        in_bytes[0] = in_bytes[0] & 0b01111111
        int_in = int.from_bytes(in_bytes, "big") << 1
        return int.to_bytes(int_in, len(in_bytes), "big")

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
# Version ID A and C: DES variant
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
        raise ValueError(f"Extra pad must be multiple of 8: {str(extra_pad)}")

    kbek, kbak = _c_derive(kbpk)
    enc_key = _c_encrypt(kbek, header, key, extra_pad)
    mac = _c_generate_mac(kbak, header, enc_key)
    return header + enc_key.hex().upper() + mac.hex().upper()


def _c_derive(kbpk: bytes) -> Tuple[bytes, bytes]:
    """Derive Key Block Encryption and Authentication Keys"""
    return (
        _tools.xor(kbpk, b"\x45" * len(kbpk)),  # Key Block Encryption Key
        _tools.xor(kbpk, b"\x4D" * len(kbpk)),  # Key Block Authentication Key
    )


def _c_encrypt(kbek: bytes, header: str, key: bytes, extra_pad: int) -> bytes:
    """Encrypt key using KBEK"""
    key_length = (len(key) * 8).to_bytes(2, "big")
    random_data = _secrets.token_bytes(6 + extra_pad)
    return _des.encrypt_tdes_cbc(
        kbek, header.encode("ascii")[:8], key_length + key + random_data
    )


def _c_decrypt(kbek: bytes, header: str, enc_key: bytes) -> bytes:
    """Decrypt key using KBEK. Return decrypted key."""
    key_data = _des.decrypt_tdes_cbc(kbek, header.encode("ascii")[:8], enc_key)

    key_length = int.from_bytes(key_data[0:2], "big")
    if key_length < 64 or key_length % 64 != 0:
        raise ValueError(f"Decrypted key length is invalid: '{str(key_length)}'")

    key = key_data[2 : (key_length // 8) + 2]
    if len(key) != key_length // 8:
        raise ValueError(f"Decrypted key length is invalid: '{key.hex().upper()}'")

    return key


def _c_generate_mac(kbak: bytes, header: str, enc_key: bytes) -> bytes:
    """Generate MAC using KBAK"""
    return _mac.generate_cbc_mac(kbak, header.encode("ascii") + enc_key, 1, 4)


class Header:
    _mac_len = {"A": 4, "B": 8, "C": 4, "D": 16}

    _block_size = {"A": 8, "B": 8, "C": 8, "D": 16}

    _valid_key_sizes = {
        "A": {8, 16, 24},
        "B": {16, 24},
        "C": {8, 16, 24},
        "D": {16, 24, 32},
    }

    def __init__(
        self,
        version_id: str = "B",
        key_usage: str = "00",
        algorithm: str = "0",
        mode_of_use: str = "0",
        version_num: str = "00",
        exportability: str = "0",
        reserved: str = "00",
        block_len: str = "0000",
    ) -> None:
        self.version_id = version_id
        self.block_len = block_len
        self.key_usage = key_usage
        self.algorithm = algorithm
        self.mode_of_use = mode_of_use
        self.version_num = version_num
        self.exportability = exportability
        self.reserved = reserved

    @property
    def mac_len(self) -> int:
        return self._mac_len[self.version_id]

    @property
    def algorithm_block_size(self) -> int:
        return self._block_size[self.version_id]

    @property
    def version_id(self) -> str:
        return self._version_id

    @version_id.setter
    def version_id(self, version_id: str) -> None:
        if version_id not in ("A", "B", "C", "D"):
            raise ValueError(f"Version ID is not supported: '{version_id}'")
        self._version_id = version_id

    @property
    def block_len(self) -> str:
        return self._block_len

    @block_len.setter
    def block_len(self, block_len: str) -> None:
        if len(block_len) != 4 or not _tools.ascii_numeric(block_len):
            raise ValueError(f"Block length is invalid: '{block_len}'")
        self._block_len = block_len

    @property
    def key_usage(self) -> str:
        return self._key_usage

    @key_usage.setter
    def key_usage(self, key_usage: str) -> None:
        if len(key_usage) != 2 or not _tools.ascii_alphanumeric(key_usage):
            raise ValueError(f"Key Usage is invalid: '{key_usage}'")
        self._key_usage = key_usage

    @property
    def algorithm(self) -> str:
        return self._algorithm

    @algorithm.setter
    def algorithm(self, algorithm: str) -> None:
        if len(algorithm) != 1 or not _tools.ascii_alphanumeric(algorithm):
            raise ValueError(f"Algorithm is invalid: '{algorithm}'")
        self._algorithm = algorithm

    @property
    def mode_of_use(self) -> str:
        return self._mode_of_use

    @mode_of_use.setter
    def mode_of_use(self, mode_of_use: str) -> None:
        if len(mode_of_use) != 1 or not _tools.ascii_alphanumeric(mode_of_use):
            raise ValueError(f"Mode of use is invalid: '{mode_of_use}'")
        self._mode_of_use = mode_of_use

    @property
    def version_num(self) -> str:
        return self._version_num

    @version_num.setter
    def version_num(self, version_num: str) -> None:
        if len(version_num) != 2 or not _tools.ascii_alphanumeric(version_num):
            raise ValueError(f"Version number is invalid: '{version_num}'")
        self._version_num = version_num

    @property
    def exportability(self) -> str:
        return self._exportability

    @exportability.setter
    def exportability(self, exportability: str) -> None:
        if len(exportability) != 1 or not _tools.ascii_alphanumeric(exportability):
            raise ValueError(f"Exportability is invalid: '{exportability}'")
        self._exportability = exportability

    @property
    def reserved(self) -> str:
        return self._reserved

    @reserved.setter
    def reserved(self, reserved: str) -> None:
        if len(reserved) != 2 or not _tools.ascii_alphanumeric(reserved):
            raise ValueError(f"Reserved field is invalid: '{reserved}'")
        self._reserved = reserved

    def dump(self, key_length: int, extra_pad: int = 0) -> str:
        """Format TR-31 header into string"""

        if key_length not in self._valid_key_sizes[self.version_id]:
            valid_sizes = ", ".join(map(str, self._valid_key_sizes[self.version_id]))
            raise ValueError(
                f"Key must be {valid_sizes} bytes long for key block version {self.version_id}"
            )

        block_size = self.algorithm_block_size
        if extra_pad % block_size != 0:
            raise ValueError(
                f"Extra pad must be multiple of {str(block_size)} "
                f"for key block version {self.version_id}"
            )

        minimum_pad = block_size - ((2 + key_length) % block_size)

        block_len = (
            16  # mandatory header
            + 4  # key length's length in ASCII
            + (key_length * 2)
            + (minimum_pad * 2)
            + (extra_pad * 2)
            + (self.mac_len * 2)
        )

        if block_len > 9992:
            ValueError(f"Key block length {str(block_len)} exceeds maximum of 9992")

        return (
            self.version_id
            + str(block_len).zfill(4)
            + self.key_usage
            + self.algorithm
            + self.mode_of_use
            + self.version_num
            + self.exportability
            + "00"  # Number of optional blocks
            + self.reserved
        )

    def load(self, key_block: str) -> int:
        """Load TR-31 header from key block string"""

        if not _tools.ascii_alphanumeric(key_block[:16]):
            raise ValueError(f"Header must be ASCII alphanumeric: '{key_block[:16]}'")

        if len(key_block) % 8 != 0:
            raise ValueError(
                f"Key block must be multiple of 8: '{str(len(key_block))}'"
            )

        if len(key_block) < 16:
            raise ValueError("Header must be at a minimum 16 characters long")

        self.version_id = key_block[0]
        self.block_len = key_block[1:5]
        self.key_usage = key_block[5:7]
        self.algorithm = key_block[7]
        self.mode_of_use = key_block[8]
        self.version_num = key_block[9:11]
        self.exportability = key_block[11]
        self.reserved = key_block[14:16]

        return 16


class TR31KeyBlock:
    def __init__(self, kbpk: bytes, header: Optional[Header] = None) -> None:
        self.kbpk = kbpk
        self.header = header or Header()

    def wrap(self, key: bytes, extra_pad: int = 0) -> str:
        """Generate TR-31 key block.

        Parameters
        ----------
        key : bytes
            A key to be wrapped.
            Must be a valid DES key for version A, B and C.
            Must be a valid AES key for version D.
        extra_pad : int, optional
            Add a number of extra bytes of random data to
            the key to mask true key length.
            Must be multiple of 8 for version A, B and C (DES).
            Must be multiple of 16 for version D (AES).
            Default 0.
            For example, to make double DES key appear as
            a triple DES set extra_pad to 8.

        Returns
        -------
        key_block : str
            Key formatted in a TR-31 key block and encrypted
            under the KBPK.

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

        if extra_pad % self.header.algorithm_block_size != 0:
            raise ValueError(
                f"Extra pad must be multiple of {str(self.header.algorithm_block_size)}: '{str(extra_pad)}'"
            )

        try:
            wrap = self._wrap_dispatch[self.header.version_id]
        except KeyError:
            raise ValueError(
                f"Key block version ID is not supported: '{self.header.version_id}'"
            )

        return wrap(self, self.header.dump(len(key), extra_pad), key, extra_pad)

    def unwrap(self, key_block: str) -> bytes:
        try:
            key_block_len = int(key_block[1:5])
        except ValueError:
            raise ValueError(f"Key block length is invalid: '{key_block[1:5]}'")

        if key_block_len != len(key_block):
            raise ValueError(
                f"Key block length '{key_block[1:5]}' "
                f"doesn't match data length '{str(key_block_len)}'"
            )

        header_len = self.header.load(key_block)
        mac_len = self.header.mac_len
        block_size = self.header.algorithm_block_size
        key_block_mac = key_block[header_len:][-mac_len * 2 :]
        key_block_key = key_block[header_len:][: -mac_len * 2]

        try:
            received_mac = bytes.fromhex(key_block_mac)
        except ValueError:
            raise ValueError(f"Key block MAC is invalid: '{key_block_mac}'")

        if len(received_mac) != mac_len:
            raise ValueError(f"Key block MAC is invalid: '{key_block_mac}'")

        try:
            enc_key = bytes.fromhex(key_block_key)
        except ValueError:
            raise ValueError(f"Encrypted key is invalid: '{key_block_key}'")

        if len(enc_key) < block_size or len(enc_key) % block_size != 0:
            raise ValueError(
                f"Encrypted key length must be multiple of {str(block_size)}: '{key_block_key}'"
            )

        try:
            unwrap = self._unwrap_dispatch[self.header.version_id]
        except KeyError:
            raise ValueError(
                f"Key block version ID is not supported: '{self.header.version_id}'"
            )

        return unwrap(self, key_block[:header_len], enc_key, received_mac)

    # Version B

    def _b_wrap(self, header: str, key: bytes, extra_pad: int = 0) -> str:
        """Wrap key into TR-31 key block version B"""

        if len(self.kbpk) not in (16, 24):
            raise ValueError(
                f"KBPK must be a double or triple DES key: '{str(len(self.kbpk))}'"
            )

        if len(key) not in (16, 24):
            raise ValueError(
                f"Key must be a double or triple DES key: '{str(len(key))}'"
            )

        if len(key) > len(self.kbpk):
            raise ValueError(f"Key must not be longer than KBPK: '{str(len(key))}'")

        kbek, kbak = _b_derive(self.kbpk)
        pad = _secrets.token_bytes(6 + extra_pad)
        mac = _b_generate_mac(kbak, header, key, pad)
        enc_key = _b_encrypt(kbek, key, mac, pad)
        return header + enc_key.hex().upper() + mac.hex().upper()

    def _b_unwrap(self, header: str, enc_key: bytes, received_mac: bytes) -> bytes:
        """Unwrap key from TR-31 key block version B"""

        if len(self.kbpk) not in (16, 24):
            raise ValueError(
                f"KBPK must be a double or triple DES key: '{str(len(self.kbpk))}'"
            )

        kbek, kbak = _b_derive(self.kbpk)
        key, pad = _b_decrypt(kbek, enc_key, received_mac)
        mac = _b_generate_mac(kbak, header, key, pad)
        if mac != received_mac:
            raise ValueError(
                f"Key block MAC does not match generated MAC: '{mac.hex().upper()}'"
            )

        return key

    # Version A, C.

    def _c_wrap(self, header: str, key: bytes, extra_pad: int = 0) -> str:
        """Wrap key into TR-31 key block version A or C"""

        if len(self.kbpk) not in (8, 16, 24):
            raise ValueError(
                f"KBPK must be a single, double or triple DES key: '{str(len(self.kbpk))}'"
            )

        if len(key) not in (8, 16, 24):
            raise ValueError(
                f"Key must be a single, double or triple DES key: '{str(len(key))}'"
            )

        if len(key) > len(self.kbpk):
            raise ValueError(f"Key must not be longer than KBPK: '{str(len(key))}'")

        kbek, kbak = _c_derive(self.kbpk)
        enc_key = _c_encrypt(kbek, header, key, extra_pad)
        mac = _c_generate_mac(kbak, header, enc_key)
        return header + enc_key.hex().upper() + mac.hex().upper()

    def _c_unwrap(self, header: str, enc_key: bytes, received_mac: bytes) -> bytes:
        """Unwrap key from TR-31 key block version A or C"""

        if len(self.kbpk) not in (8, 16, 24):
            raise ValueError(
                f"KBPK must be a single, double or triple DES key: '{str(len(self.kbpk))}'"
            )

        kbek, kbak = _c_derive(self.kbpk)
        mac = _c_generate_mac(kbak, header, enc_key)
        if mac != received_mac:
            raise ValueError(
                f"Key block MAC does not match generated MAC: '{mac.hex().upper()}'"
            )
        key = _c_decrypt(kbek, header, enc_key)

        return key

    _wrap_dispatch: Dict[str, Callable[["TR31KeyBlock", str, bytes, int], str]] = {
        "A": _c_wrap,
        "B": _b_wrap,
        "C": _c_wrap,
    }

    _unwrap_dispatch: Dict[
        str, Callable[["TR31KeyBlock", str, bytes, bytes], bytes]
    ] = {
        "A": _c_unwrap,
        "B": _b_unwrap,
        "C": _c_unwrap,
    }
