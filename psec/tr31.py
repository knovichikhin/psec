import secrets as _secrets
from typing import Callable, Dict, Optional, Tuple

from psec import des as _des
from psec import mac as _mac
from psec import tools as _tools

__all__ = ["wrap", "unwrap", "KeyBlock", "Header"]


def derive_tdes_cmac_subkey(key: bytes) -> Tuple[bytes, bytes]:
    """Derive two subkeys from a DES key. Each subkey is 8 bytes."""

    def shift_left_1(in_bytes: bytes) -> bytes:
        """Shift byte array left by 1 bit"""
        in_bytes = bytearray(in_bytes)
        in_bytes[0] = in_bytes[0] & 0b01111111
        int_in = int.from_bytes(in_bytes, "big") << 1
        return int.to_bytes(int_in, len(in_bytes), "big")

    r64 = b"\x00\x00\x00\x00\x00\x00\x00\x1B"

    s = _des.encrypt_tdes_ecb(key, b"\x00" * 8)

    if s[0] & 0b10000000:
        k1 = _tools.xor(shift_left_1(s), r64)
    else:
        k1 = shift_left_1(s)

    if k1[0] & 0b10000000:
        k2 = _tools.xor(shift_left_1(k1), r64)
    else:
        k2 = shift_left_1(k1)

    return k1, k2


class TR31Header:
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
        if version_id not in {"A", "B", "C", "D"}:
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
    """
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
    """

    def __init__(self, kbpk: bytes, header: Optional[TR31Header] = None) -> None:
        self.kbpk = kbpk
        self.header = header or TR31Header()

    def wrap(self, key: bytes, extra_pad: int = 0) -> str:
        r"""Wrap key into a TR-31 key block.

        Parameters
        ----------
        key : bytes
            A key to be wrapped.
            Must be a valid DES key for versions A, B and C.
            Must be a valid AES key for version D.
        extra_pad : int, optional
            Add extra bytes of random data to
            the key to mask its true length.
            Must be multiple of 8 for versions A, B and C (DES).
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
        >>> h = psec.tr31.TR31Header("B", "P0", "T","E","00","E")
        >>> kb = psec.tr31.TR31KeyBlock(kbpk=b"\xFF" * 16, header=h)
        >>> kb.wrap(key=b"\xEE" * 16)  # doctest: +SKIP
        'B0080P0TE00E0000E30027FBC014F6B22182E2EA95E245D261CA45260DF616F7C8F203EC19BD1197'
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
        r"""Unwrap key from a TR-31 key block.

        Parameters
        ----------
        key_block : str
            A TR-31 key block.

        Returns
        -------
        key : bytes
            Unwrapped key.
            A DES key for versions A, B and C.
            An AES key for version D.

        Notes
        -----
        TR-31 version C is identical to version A with exception
        of some of the key headers values that have been clarified.

        Examples
        --------
        >>> import psec
        >>> kb = psec.tr31.TR31KeyBlock(kbpk=b"\xFF" * 16)
        >>> kb.unwrap("B0080P0TE00E0000E30027FBC014F6B22182E2EA95E245D261CA45260DF616F7C8F203EC19BD1197")
        b'\xee\xee\xee\xee\xee\xee\xee\xee\xee\xee\xee\xee\xee\xee\xee\xee'
        """

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

        block_size = self.header.algorithm_block_size
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

        if len(self.kbpk) not in {16, 24}:
            raise ValueError(
                f"KBPK must be a double or triple DES key: '{str(len(self.kbpk))}'"
            )

        if len(key) not in {16, 24}:
            raise ValueError(
                f"Key must be a double or triple DES key: '{str(len(key))}'"
            )

        if len(key) > len(self.kbpk):
            raise ValueError(f"Key must not be longer than KBPK: '{str(len(key))}'")

        # Derive Key Block Encryption and Authentication Keys
        kbek, kbak = self._b_derive()

        # Format key data: 2 byte key length measure in bits + key + pad
        pad = _secrets.token_bytes(6 + extra_pad)
        clear_key_data = (len(key) * 8).to_bytes(2, "big") + key + pad

        # Generate MAC
        mac = self._b_generate_mac(kbak, header, clear_key_data)

        # Encrypt key data
        enc_key = _des.encrypt_tdes_cbc(kbek, mac, clear_key_data)

        return header + enc_key.hex().upper() + mac.hex().upper()

    def _b_unwrap(self, header: str, enc_key: bytes, received_mac: bytes) -> bytes:
        """Unwrap key from TR-31 key block version B"""

        if len(self.kbpk) not in {16, 24}:
            raise ValueError(
                f"KBPK must be a double or triple DES key: '{str(len(self.kbpk))}'"
            )

        # Derive Key Block Encryption and Authentication Keys
        kbek, kbak = self._b_derive()

        # Decrypt key data
        clear_key_data = _des.decrypt_tdes_cbc(kbek, received_mac, enc_key)

        # Validate MAC
        mac = self._b_generate_mac(kbak, header, clear_key_data)
        if mac != received_mac:
            raise ValueError(
                f"Key block MAC does not match generated MAC: '{mac.hex().upper()}'"
            )

        # Extract key from key data: 2 byte key length measured in bits + key + pad
        key_length = int.from_bytes(clear_key_data[0:2], "big")
        if key_length < 8 or key_length % 8 != 0:
            raise ValueError(f"Decrypted key length is invalid: '{str(key_length)}'")

        key = clear_key_data[2 : (key_length // 8) + 2]
        if len(key) != key_length // 8:
            raise ValueError(f"Decrypted key length is invalid: '{str(key_length)}'")

        return key

    def _b_derive(self) -> Tuple[bytes, bytes]:
        """Derive Key Block Encryption and Authentication Keys"""
        # byte 0 = a counter increment for each block of kbpk, start at 1
        # byte 1-2 = key usage indicator
        #   - 0000 = encryption
        #   - 0001 = MAC
        # byte 3 = separator, set to 0
        # byte 4-5 = algorithm indicator
        #   - 0000 = 2-Key TDES
        #   - 0001 = 3-Key TDES
        # byte 6-7 = key length in bits
        #   - 0080 = 2-Key TDES
        #   - 00C0 = 3-Key TDES
        kd_input = bytearray(b"\x01\x00\x00\x00\x00\x00\x00\x80")

        # Adjust for 3-key TDES
        if len(self.kbpk) == 24:
            kd_input[4:6] = b"\x00\x01"
            kd_input[6:8] = b"\x00\xC0"

        kbek = bytearray()  # encryption key
        kbak = bytearray()  # authentication key

        k1, _ = derive_tdes_cmac_subkey(self.kbpk)

        for i in range(1, len(self.kbpk) // 8 + 1):
            # Counter is incremented for each 8 byte block
            kd_input[0] = i

            # Encryption key
            kd_input[1:3] = b"\x00\x00"
            kbek += _mac.generate_cbc_mac(self.kbpk, _tools.xor(kd_input, k1), 1)

            # Authentication key
            kd_input[1:3] = b"\x00\x01"
            kbak += _mac.generate_cbc_mac(self.kbpk, _tools.xor(kd_input, k1), 1)

        return bytes(kbek), bytes(kbak)

    def _b_generate_mac(self, kbak: bytes, header: str, key_data: bytes) -> bytes:
        """Generate MAC using KBAK"""
        km1, _ = derive_tdes_cmac_subkey(kbak)
        mac_data = header.encode("ascii") + key_data
        mac_data = mac_data[:-8] + _tools.xor(mac_data[-8:], km1)
        mac = _mac.generate_cbc_mac(kbak, mac_data, 1)
        return mac

    # Version A, C.

    def _c_wrap(self, header: str, key: bytes, extra_pad: int = 0) -> str:
        """Wrap key into TR-31 key block version A or C"""

        if len(self.kbpk) not in {8, 16, 24}:
            raise ValueError(
                f"KBPK must be a single, double or triple DES key: '{str(len(self.kbpk))}'"
            )

        if len(key) not in {8, 16, 24}:
            raise ValueError(
                f"Key must be a single, double or triple DES key: '{str(len(key))}'"
            )

        if len(key) > len(self.kbpk):
            raise ValueError(f"Key must not be longer than KBPK: '{str(len(key))}'")

        # Derive Key Block Encryption and Authentication Keys
        kbek, kbak = self._c_derive()

        # Format key data: 2 byte key length measure in bits + key + pad
        pad = _secrets.token_bytes(6 + extra_pad)
        clear_key_data = (len(key) * 8).to_bytes(2, "big") + key + pad

        # Encrypt key data
        enc_key = _des.encrypt_tdes_cbc(
            kbek, header.encode("ascii")[:8], clear_key_data
        )

        # Generate MAC
        mac = self._c_generate_mac(kbak, header, enc_key)

        return header + enc_key.hex().upper() + mac.hex().upper()

    def _c_unwrap(self, header: str, enc_key: bytes, received_mac: bytes) -> bytes:
        """Unwrap key from TR-31 key block version A or C"""

        if len(self.kbpk) not in {8, 16, 24}:
            raise ValueError(
                f"KBPK must be a single, double or triple DES key: '{str(len(self.kbpk))}'"
            )

        # Derive Key Block Encryption and Authentication Keys
        kbek, kbak = self._c_derive()

        # Validate MAC
        mac = self._c_generate_mac(kbak, header, enc_key)
        if mac != received_mac:
            raise ValueError(
                f"Key block MAC does not match generated MAC: '{mac.hex().upper()}'"
            )

        # Decrypt key data
        clear_key_data = _des.decrypt_tdes_cbc(
            kbek, header.encode("ascii")[:8], enc_key
        )

        # Extract key from key data: 2 byte key length measured in bits + key + pad
        key_length = int.from_bytes(clear_key_data[0:2], "big")
        if key_length < 8 or key_length % 8 != 0:
            raise ValueError(f"Decrypted key length is invalid: '{str(key_length)}'")

        key = clear_key_data[2 : (key_length // 8) + 2]
        if len(key) != key_length // 8:
            raise ValueError(f"Decrypted key length is invalid: '{str(key_length)}'")

        return key

    def _c_derive(self) -> Tuple[bytes, bytes]:
        """Derive Key Block Encryption and Authentication Keys"""
        return (
            _tools.xor(self.kbpk, b"\x45" * len(self.kbpk)),  # Encryption Key
            _tools.xor(self.kbpk, b"\x4D" * len(self.kbpk)),  # Authentication Key
        )

    def _c_generate_mac(self, kbak: bytes, header: str, enc_key: bytes) -> bytes:
        """Generate MAC using KBAK"""
        return _mac.generate_cbc_mac(kbak, header.encode("ascii") + enc_key, 1, 4)

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
