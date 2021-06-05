import secrets as _secrets
import typing as _typing

from psec import des as _des
from psec import mac as _mac
from psec import tools as _tools

__all__ = ["KeyBlock", "KeyBlockError", "Header", "HeaderError"]


class HeaderError(ValueError):
    """Subclass of ValueError that indicates error in processing TR-31 header data."""

    pass


class KeyBlockError(ValueError):
    """Subclass of ValueError that indicates error in processing TR-31 key block data."""

    pass


class Blocks(_typing.MutableMapping[str, str]):
    def __init__(self) -> None:
        self._blocks: _typing.Dict[str, str] = {}

    def __len__(self) -> int:
        return len(self._blocks)

    def __getitem__(self, key: str) -> str:
        if key in self._blocks:
            return self._blocks[key]
        raise KeyError(key)

    def __setitem__(self, key: str, item: str) -> None:
        if len(key) != 2 or not _tools.ascii_alphanumeric(key):
            raise HeaderError(
                f"Block ID ({key}) is invalid. Expecting 2 alphanumeric characters."
            )
        if not _tools.ascii_printable(item):
            raise HeaderError(
                f"Block {key} data is invalid. Expecting ASCII printable characters. "
                f"Data: '{item}'"
            )
        self._blocks[key] = item

    def __delitem__(self, key: str) -> None:
        del self._blocks[key]

    def __iter__(self) -> _typing.Iterator[str]:
        return iter(self._blocks)

    def __contains__(self, key: object) -> bool:
        return key in self._blocks

    def __repr__(self) -> str:
        return repr(self._blocks)

    def dump(self, algo_block_size: int) -> _typing.Tuple[int, str]:
        """Format TR-31 header optional blocks into a string.

        Parameters
        ----------
        algo_block_size : int
            TR-31 algorithm block size. 8 for TDES and 16 for AES.
            Required because produced block data must be multiple of
            algorithm encryption block size.

        Returns
        -------
        blocks_num : int
            Number of blocks included in the produced string.
        blocks : str
            String that contains TR-31 header optional blocks.

        Raises
        ------
        HeaderError
        """

        blocks_list: _typing.List[str] = []
        for block_id, block_data in self.items():
            blocks_list.append(block_id)

            # Length is encoded in a single hexchar pair for <=255 fields.
            # +4 is to include block ID and length itself into the length.
            if len(block_data) + 4 <= 255:
                blocks_list.append(
                    (len(block_data) + 4).to_bytes(1, "big").hex().upper()
                )
            else:
                # For fields longer than 255 construct an extended length
                # that consits of length of length and only then actual length.
                # +10 is to include block ID, extended length indicator (00),
                # length of length (02) and length itself (e.g. 0FFF).
                blocks_list.append("0002")
                try:
                    blocks_list.append(
                        (len(block_data) + 10).to_bytes(2, "big").hex().upper()
                    )
                except OverflowError:
                    raise HeaderError(
                        f"Block {block_id} length ({str(len(block_data))}) is too long."
                    ) from None

            blocks_list.append(block_data)

        blocks = "".join(blocks_list)

        # If total block data is not multiple of encryption algo block size
        # then need to add a Pad Block.
        if len(blocks) % algo_block_size != 0:
            pad_num = algo_block_size - ((len(blocks) + 4) % algo_block_size)
            pb_block = (
                "PB" + (4 + pad_num).to_bytes(1, "big").hex().upper() + (pad_num * "0")
            )
            pb_block_count = 1
        else:
            pb_block = ""
            pb_block_count = 0

        if len(self) + pb_block_count > 99:
            raise HeaderError(
                f"Number of blocks ({str(len(self) + pb_block_count)}) "
                f"exceeds limit of 99."
            )

        return len(self) + pb_block_count, blocks + pb_block

    def load(self, blocks_num: int, blocks: str) -> int:
        """Load TR-31 header optional blocks from a string.

        Parameters
        ----------
        blocks_num : int
            Number of expected optional blocks within the supplied string.
        blocks : str
            String that contains TR-31 header optional blocks.

        Returns
        -------
        blocks_len : int
            Length of parsed optional blocks data within supplied input string.

        Raises
        ------
        HeaderError

        Notes
        -----
        This method clears all current optional blocks before loading new ones.
        """

        def parse_extended_len(
            block_id: str, blocks: str, i: int
        ) -> _typing.Tuple[int, int]:
            # Get 2 character long optional block length of length.
            # E.g. if a block's length is 0190 then this field is set to 02
            # to indicate that the length consists of 2 hexchar pairs.
            block_len_len_s = blocks[i : i + 2]
            if len(block_len_len_s) != 2 or not _tools.ascii_hexchar(block_len_len_s):
                raise HeaderError(
                    f"Block {block_id} length of length ({block_len_len_s}) is malformed. "
                    f"Expecting 2 hexchars."
                )
            i += 2

            block_len_len = int(block_len_len_s, 16) * 2
            if block_len_len == 0:
                raise HeaderError(f"Block {block_id} length of length must not be 0.")

            # Extract actual block length
            block_len_s = blocks[i : i + block_len_len]
            if len(block_len_s) != block_len_len or not _tools.ascii_hexchar(
                block_len_s
            ):
                raise HeaderError(
                    f"Block {block_id} length ({block_len_s}) is malformed. "
                    f"Expecting {str(block_len_len)} hexchars."
                )

            # Block length includes ID, 00 length indicator,
            # lenght of length and actual length in it.
            # Remove that to return block data length.
            block_len = int(block_len_s, 16)
            return (block_len - 6 - block_len_len), i + block_len_len

        # Remove any existing blocks before loading new ones
        self.clear()

        i = 0
        for _ in range(0, blocks_num):
            # Get 2 character long optional block ID
            block_id = blocks[i : i + 2]
            if len(block_id) != 2:
                raise HeaderError(f"Block ID ({block_id}) is malformed.")
            i += 2

            # Get 2 character long optional block length.
            block_len_s = blocks[i : i + 2]
            if len(block_len_s) != 2 or not _tools.ascii_hexchar(block_len_s):
                raise HeaderError(
                    f"Block {block_id} length ({block_len_s}) is malformed. "
                    f"Expecting 2 hexchars."
                )
            i += 2

            # If the length is 00 then block length consists of multiple bytes.
            # Otherwise, the first length byte is the length.
            block_len = int(block_len_s, 16)
            if block_len == 0:
                block_len, i = parse_extended_len(block_id, blocks, i)
            else:
                # Exclude block ID and block length to get block data length
                block_len -= 4

            if block_len < 0:
                raise HeaderError(
                    f"Block {block_id} length does not include block ID and length."
                )

            block_data = blocks[i : i + block_len]
            if len(block_data) != block_len:
                raise HeaderError(
                    f"Block {block_id} data is malformed. "
                    f"Received {str(len(block_data))}/{str(block_len)}. "
                    f"Block data: '{block_data}'"
                )
            i += block_len

            # Do not add Pad Block. It's there to make optional blocks
            # multiple of encryption block size. It does not cary any data.
            if block_id.upper() != "PB":
                self[block_id] = block_data

        return i


class Header:
    """TR-31 header.

    Parameters
    ----------
    version_id : str
        Identifies the version of the key block, which defines the method
        by which it is cryptographically protected and the content and
        layout of the block:

            - A - TDES variant. Deprecated and should not be used for new applications.
            - B - TDES key derivation. Preferred TDES implementation.
            - C - TDES variant. Same as A.
            - D - AES key derivation

    key_usage : str
        Provides information about the intended function of the protected
        key/sensitive data. For example, caculating MAC.
    algorithm: str
        The approved algorithm for which the protected key may be used.
    mode_of_use: str
        Defines the operation the protected key can perform. For example,
        a MAC key may be limited to verification only.
    version_num: str
        Two-digit ASCII character version number, optionally used to
        indicate that contents of the key block is a component,
        or to prevent re-injection of old keys.
        Not to be confused with version ID.
    exportability: str
        Defines whether the protected key may be transferred outside
        the cryptographic domain in which the key is found.

    Attributes
    ----------
    version_id : str
        Identifies the version of the key block, which defines the method
        by which it is cryptographically protected and the content and
        layout of the block:

            - A = TDES variant. Deprecated and should not be used for new applications.
            - B = TDES key derivation. Preferred TDES implementation.
            - C = TDES variant. Same as A.
            - D = AES key derivation

    key_usage : str
        Provides information about the intended function of the protected
        key/sensitive data. For example, caculating MAC.
    algorithm: str
        The approved algorithm for which the protected key may be used.
    mode_of_use: str
        Defines the operation the protected key can perform. For example,
        a MAC key may be limited to verification only.
    version_num: str
        Two-digit ASCII character version number, optionally used to
        indicate that contents of the key block is a component,
        or to prevent re-injection of old keys.
        Not to be confused with version ID.
    exportability: str
        Defines whether the protected key may be transferred outside
        the cryptographic domain in which the key is found.
    blocks : Blocks
        A dictionary of optional blocks that contain additional
        information about the key block.
    """

    _algo_mac_len = {"A": 4, "B": 8, "C": 4, "D": 16}
    _algo_block_size = {"A": 8, "B": 8, "C": 8, "D": 16}
    _algo_key_sizes = {
        "A": frozenset([8, 16, 24]),
        "B": frozenset([8, 16, 24]),
        "C": frozenset([8, 16, 24]),
        "D": frozenset([16, 24, 32]),
    }

    def __init__(
        self,
        version_id: str = "B",
        key_usage: str = "00",
        algorithm: str = "0",
        mode_of_use: str = "0",
        version_num: str = "00",
        exportability: str = "N",
    ) -> None:
        self.version_id = version_id
        self.key_usage = key_usage
        self.algorithm = algorithm
        self.mode_of_use = mode_of_use
        self.version_num = version_num
        self.exportability = exportability
        self._reserved = "00"
        self.blocks = Blocks()

    def __str__(self) -> str:
        blocks_num, blocks = self.blocks.dump(self._algo_block_size[self.version_id])
        return (
            self.version_id
            + str(16 + len(blocks)).zfill(4)
            + self.key_usage
            + self.algorithm
            + self.mode_of_use
            + self.version_num
            + self.exportability
            + str(blocks_num).zfill(2)
            + self.reserved
            + blocks
        )

    @property
    def version_id(self) -> str:
        """Identifies the version of the key block, which defines the method
        by which it is cryptographically protected and the content and
        layout of the block.
        """
        return self._version_id

    @version_id.setter
    def version_id(self, version_id: str) -> None:
        if version_id not in {"A", "B", "C", "D"}:
            raise HeaderError(f"Version ID ({version_id}) is not supported.")
        self._version_id = version_id

    @property
    def key_usage(self) -> str:
        """Provides information about the intended function of the protected
        key/sensitive data. For example, caculating MAC.
        """
        return self._key_usage

    @key_usage.setter
    def key_usage(self, key_usage: str) -> None:
        if len(key_usage) != 2 or not _tools.ascii_alphanumeric(key_usage):
            raise HeaderError(f"Key usage ({key_usage}) is invalid.")
        self._key_usage = key_usage

    @property
    def algorithm(self) -> str:
        """The approved algorithm for which the protected key may be used."""
        return self._algorithm

    @algorithm.setter
    def algorithm(self, algorithm: str) -> None:
        if len(algorithm) != 1 or not _tools.ascii_alphanumeric(algorithm):
            raise HeaderError(f"Algorithm ({algorithm}) is invalid.")
        self._algorithm = algorithm

    @property
    def mode_of_use(self) -> str:
        """Defines the operation the protected key can perform. For example,
        a MAC key may be limited to verification only.
        """
        return self._mode_of_use

    @mode_of_use.setter
    def mode_of_use(self, mode_of_use: str) -> None:
        if len(mode_of_use) != 1 or not _tools.ascii_alphanumeric(mode_of_use):
            raise HeaderError(f"Mode of use ({mode_of_use}) is invalid.")
        self._mode_of_use = mode_of_use

    @property
    def version_num(self) -> str:
        """Two-digit ASCII character version number, optionally used to
        indicate that contents of the key block is a component,
        or to prevent re-injection of old keys.
        Not to be confused with version ID.
        """
        return self._version_num

    @version_num.setter
    def version_num(self, version_num: str) -> None:
        if len(version_num) != 2 or not _tools.ascii_alphanumeric(version_num):
            raise HeaderError(f"Version number ({version_num}) is invalid.")
        self._version_num = version_num

    @property
    def exportability(self) -> str:
        """Defines whether the protected key may be transferred outside
        the cryptographic domain in which the key is found.
        """
        return self._exportability

    @exportability.setter
    def exportability(self, exportability: str) -> None:
        if len(exportability) != 1 or not _tools.ascii_alphanumeric(exportability):
            raise HeaderError(f"Exportability ({exportability}) is invalid.")
        self._exportability = exportability

    @property
    def reserved(self) -> str:
        """This field is reserved for future use.
        It should be filled with zeroes.
        """
        return self._reserved

    def dump(self, key_len: int) -> str:
        """Format TR-31 header into a key block string

        Parameters
        ----------
        key_len : int
            Length of key to be wrapped into this key block.
            Key length is required to determine correct key block length.

        Returns
        -------
        header : str
            String that contains TR-31 header.

        Raises
        ------
        HeaderError
        """

        if key_len not in self._algo_key_sizes[self.version_id]:
            valid_sizes = ", ".join(map(str, self._algo_key_sizes[self.version_id]))
            raise HeaderError(
                f"Key length ({str(key_len)}) must be {valid_sizes} for key block version {self.version_id}."
            )

        algo_block_size = self._algo_block_size[self.version_id]
        pad_len = algo_block_size - ((2 + key_len) % algo_block_size)

        blocks_num, blocks = self.blocks.dump(algo_block_size)

        kb_len = (
            16  # mandatory header
            + 4  # key length's length in ASCII
            + (key_len * 2)
            + (pad_len * 2)
            + (self._algo_mac_len[self.version_id] * 2)
            + len(blocks)
        )

        if kb_len > 9992:
            raise HeaderError(
                f"Total key block length ({str(kb_len)}) exceeds limit of 9992."
            )

        return (
            self.version_id
            + str(kb_len).zfill(4)
            + self.key_usage
            + self.algorithm
            + self.mode_of_use
            + self.version_num
            + self.exportability
            + str(blocks_num).zfill(2)
            + self.reserved
            + blocks
        )

    def load(self, header: str) -> int:
        """Load TR-31 header from a string

        Parameters
        ----------
        header : str
            String that contains TR-31 header information.
            Could also be a complete or incomplete TR-31 key block.

        Returns
        -------
        header_len : int
            Length of parsed header data within supplied input string.

        Raises
        ------
        HeaderError

        Notes
        -----
        This method overrides all values of the header and
        clears all prior optional blocks before loading new ones.
        """

        if not _tools.ascii_alphanumeric(header[:16]):
            raise HeaderError(
                f"Header must be ASCII alphanumeric. Header: '{header[:16]}'"
            )

        if len(header) < 16:
            raise HeaderError(
                f"Header length ({str(len(header))}) must be >=16. "
                f"Header: '{header[:16]}'"
            )

        self.version_id = header[0]
        self.key_usage = header[5:7]
        self.algorithm = header[7]
        self.mode_of_use = header[8]
        self.version_num = header[9:11]
        self.exportability = header[11]
        self._reserved = header[14:16]

        if not _tools.ascii_numeric(header[12:14]):
            raise HeaderError(
                f"Number of blocks ({header[12:14]}) is invalid. "
                f"Expecting 2 digits."
            )

        blocks_num = int(header[12:14])
        blocks_len = self.blocks.load(blocks_num, header[16:])

        return 16 + blocks_len


class KeyBlock:
    """TR-31 key block.

    Parameters
    ----------
    kbpk : bytes
        Key Block Protection Key.
        The length of the KBPK must equal or greater than the key to be protected.
        Must be 8, 16 or 24 DES key for versions A and C.
        Must be 16 or 24 DES key for versions B.
        Must be 16, 24 or 32 AES key for version D.
    header : Header or str
        TR-31 key block header either in TR-31 string format or
        as a Header class. Optional.
        A full TR-31 key block in string format can be provided
        to extract header from.

    Attributes
    ----------
    kbpk : bytes
        Key Block Protection Key.
        The length of the KBPK must equal or greater than the key to be protected.
        Must be 8, 16 or 24 DES key for versions A and C.
        Must be 16 or 24 DES key for version B.
        Must be 16, 24 or 32 AES key for version D.
    header : Header
        TR-31 key block header.
    """

    _algo_mac_len = {"A": 4, "B": 8, "C": 4, "D": 16}
    _algo_max_key_len = {"A": 24, "B": 24, "C": 24, "D": 32}

    def __init__(
        self, kbpk: bytes, header: _typing.Optional[_typing.Union[Header, str]] = None
    ) -> None:
        self.kbpk = kbpk

        if isinstance(header, str):
            self.header = Header()
            self.header.load(header)
        elif isinstance(header, Header):
            self.header = header
        else:
            self.header = Header()

    def __str__(self) -> str:
        return str(self.header)

    def wrap(self, key: bytes, masked_key_len: _typing.Optional[int] = None) -> str:
        r"""Wrap key into a TR-31 key block version A, B or C.

        Parameters
        ----------
        key : bytes
            A key to be wrapped.
            Must be a valid DES key for versions A, B and C.
            Must be a valid AES key for version D.
        masked_key_len : int, optional
            Desired key length in bytes to mask true key length.
            Must be 8, 16 or 24 for versions A, B and C (DES).
            Must be 16, 24 or 32 for version D (AES).
            Defaults to max key size.

        Returns
        -------
        key_block : str
            Key formatted in a TR-31 key block and encrypted
            under the KBPK.

        Raises
        ------
        KeyBlockError
        HeaderError

        Notes
        -----
        TR-31 version C is identical to version A with exception
        of some of the key headers values that have been clarified.

        Examples
        --------
        >>> import psec
        >>> h = psec.tr31.Header("B", "P0", "T","E","00","N")
        >>> kb = psec.tr31.KeyBlock(kbpk=b"\xFF" * 16, header=h)
        >>> kb.wrap(key=b"\xEE" * 16)  # doctest: +SKIP
        'B0096P0TE00N0000342811F905093F2B797EB9248C1121C011C2AE41BEC63E33C9C2FDB320540D82327221AE9C5C34FB'
        >>> kb.header.version_id
        'B'
        >>> kb.header.key_usage
        'P0'
        >>> kb.header.algorithm
        'T'
        >>> kb.header.mode_of_use
        'E'
        >>> kb.header.version_num
        '00'
        >>> kb.header.exportability
        'N'
        """

        try:
            wrap = self._wrap_dispatch[self.header.version_id]
        except KeyError:
            raise KeyBlockError(
                f"Key block version ID ({self.header.version_id}) is not supported."
            ) from None

        if masked_key_len is None:
            masked_key_len = max(
                self._algo_max_key_len[self.header.version_id], len(key)
            )
        else:
            masked_key_len = max(masked_key_len, len(key))

        return wrap(
            self,
            self.header.dump(masked_key_len),
            key,
            masked_key_len - len(key),
        )

    def unwrap(self, key_block: str) -> bytes:
        r"""Unwrap key from a TR-31 key block version A, B or C.

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

        Raises
        ------
        KeyBlockError
        HeaderError

        Notes
        -----
        TR-31 version C is identical to version A with exception
        of some of the key headers values that have been clarified.

        Examples
        --------
        >>> import psec
        >>> kb = psec.tr31.KeyBlock(kbpk=b"\xFF" * 16)
        >>> kb.unwrap("B0096P0TE00N0000342811F905093F2B797EB9248C1121C011C2AE41BEC63E33C9C2FDB320540D82327221AE9C5C34FB")
        b'\xee\xee\xee\xee\xee\xee\xee\xee\xee\xee\xee\xee\xee\xee\xee\xee'
        >>> kb.header.version_id
        'B'
        >>> kb.header.key_usage
        'P0'
        >>> kb.header.algorithm
        'T'
        >>> kb.header.mode_of_use
        'E'
        >>> kb.header.version_num
        '00'
        >>> kb.header.exportability
        'N'
        """

        # Extract header from the key block
        header_len = self.header.load(key_block)

        # Verify block length
        if not _tools.ascii_numeric(key_block[1:5]):
            raise KeyBlockError(
                f"Key block header length ({key_block[1:5]}) is malformed. "
                f"Expecting 4 digits."
            )

        key_block_len = int(key_block[1:5])
        if key_block_len != len(key_block):
            raise KeyBlockError(
                f"Key block header length ({str(key_block_len)}) "
                f"doesn't match input data length ({str(len(key_block))})."
            )

        if len(key_block) % 8 != 0:
            raise KeyBlockError(
                f"Key block length ({str(len(key_block))}) must be multiple of 8."
            )

        # Extract MAC from the key block.
        # MAC length is fixed for each version ID.
        algo_mac_len = self._algo_mac_len[self.header.version_id]
        received_mac_s = key_block[header_len:][-algo_mac_len * 2 :]
        try:
            received_mac = bytes.fromhex(received_mac_s)
        except ValueError:
            raise KeyBlockError(
                f"Key block MAC must be valid hexchars. MAC: '{received_mac_s}'"
            ) from None

        if len(received_mac) != algo_mac_len:
            raise KeyBlockError(
                f"Key block MAC is malformed. "
                f"Received {str(len(received_mac_s))}/{str(algo_mac_len * 2)}. "
                f"MAC: '{received_mac_s}'"
            )

        # Extract encrypted key data from the key block.
        # Whatever is left after taking header and MAC out is the key data.
        key_data_s = key_block[header_len:][: -algo_mac_len * 2]
        try:
            key_data = bytes.fromhex(key_data_s)
        except ValueError:
            raise KeyBlockError(
                f"Encrypted key must be valid hexchars. Key data: '{key_data_s}'"
            ) from None

        try:
            unwrap = self._unwrap_dispatch[self.header.version_id]
        except KeyError:
            raise KeyBlockError(
                f"Key block version ID ({self.header.version_id}) is not supported."
            ) from None

        return unwrap(self, key_block[:header_len], key_data, received_mac)

    # Version B

    def _b_wrap(self, header: str, key: bytes, extra_pad: int) -> str:
        """Wrap key into TR-31 key block version B"""

        if len(self.kbpk) not in {16, 24}:
            raise KeyBlockError(
                f"KBPK length ({str(len(self.kbpk))}) must be 2-key or 3-key TDES."
            )

        if len(key) not in {8, 16, 24}:
            raise KeyBlockError(
                f"Key length ({str(len(key))}) must be 1-key, 2-key or 3-key TDES."
            )

        if len(key) > len(self.kbpk):
            raise KeyBlockError(
                f"Key length ({str(len(key))}) must be less than or equal to KBPK ({str(len(self.kbpk))})."
            )

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

    def _b_unwrap(self, header: str, key_data: bytes, received_mac: bytes) -> bytes:
        """Unwrap key from TR-31 key block version B"""

        if len(self.kbpk) not in {16, 24}:
            raise KeyBlockError(
                f"KBPK length ({str(len(self.kbpk))}) must be 2-key or 3-key TDES."
            )

        if len(key_data) < 16 or len(key_data) % 8 != 0:
            raise KeyBlockError(
                f"Encrypted key is malformed. Key data: '{key_data.hex().upper()}'"
            )

        # Derive Key Block Encryption and Authentication Keys
        kbek, kbak = self._b_derive()

        # Decrypt key data
        clear_key_data = _des.decrypt_tdes_cbc(kbek, received_mac, key_data)

        # Validate MAC
        mac = self._b_generate_mac(kbak, header, clear_key_data)
        if mac != received_mac:
            raise KeyBlockError(f"Key block MAC doesn't match generated MAC.")

        # Extract key from key data: 2 byte key length measured in bits + key + pad
        key_length = int.from_bytes(clear_key_data[0:2], "big")
        if key_length not in {64, 128, 192}:
            raise KeyBlockError(f"Decrypted key is invalid.")

        key_length = key_length // 8
        key = clear_key_data[2 : key_length + 2]
        if len(key) != key_length:
            raise KeyBlockError(f"Decrypted key is malformed.")

        return key

    def _b_derive(self) -> _typing.Tuple[bytes, bytes]:
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

        k1, _ = self._derive_des_cmac_subkey(self.kbpk)

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
        km1, _ = self._derive_des_cmac_subkey(kbak)
        mac_data = header.encode("ascii") + key_data
        mac_data = mac_data[:-8] + _tools.xor(mac_data[-8:], km1)
        mac = _mac.generate_cbc_mac(kbak, mac_data, 1)
        return mac

    def _derive_des_cmac_subkey(self, key: bytes) -> _typing.Tuple[bytes, bytes]:
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

    # Version A, C.

    def _c_wrap(self, header: str, key: bytes, extra_pad: int) -> str:
        """Wrap key into TR-31 key block version A or C"""

        if len(self.kbpk) not in {8, 16, 24}:
            raise KeyBlockError(
                f"KBPK length ({str(len(self.kbpk))}) must be 1-key, 2-key or 3-key TDES."
            )

        if len(key) not in {8, 16, 24}:
            raise KeyBlockError(
                f"Key length ({str(len(key))}) must be 1-key, 2-key or 3-key TDES."
            )

        if len(key) > len(self.kbpk):
            raise KeyBlockError(
                f"Key length ({str(len(key))}) must be less than or equal to KBPK ({str(len(self.kbpk))})."
            )

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

    def _c_unwrap(self, header: str, key_data: bytes, received_mac: bytes) -> bytes:
        """Unwrap key from TR-31 key block version A or C"""

        if len(self.kbpk) not in {8, 16, 24}:
            raise KeyBlockError(
                f"KBPK length ({str(len(self.kbpk))}) must be 1-key, 2-key or 3-key TDES."
            )

        if len(key_data) < 16 or len(key_data) % 8 != 0:
            raise KeyBlockError(
                f"Encrypted key is malformed. Key data: '{key_data.hex().upper()}'"
            )

        # Derive Key Block Encryption and Authentication Keys
        kbek, kbak = self._c_derive()

        # Validate MAC
        mac = self._c_generate_mac(kbak, header, key_data)
        if mac != received_mac:
            raise KeyBlockError(f"Key block MAC doesn't match generated MAC.")

        # Decrypt key data
        clear_key_data = _des.decrypt_tdes_cbc(
            kbek, header.encode("ascii")[:8], key_data
        )

        # Extract key from key data: 2 byte key length measured in bits + key + pad
        key_length = int.from_bytes(clear_key_data[0:2], "big")
        if key_length not in {64, 128, 192}:
            raise KeyBlockError(f"Decrypted key is invalid.")

        key_length = key_length // 8
        key = clear_key_data[2 : key_length + 2]
        if len(key) != key_length:
            raise KeyBlockError(f"Decrypted key is malformed.")

        return key

    def _c_derive(self) -> _typing.Tuple[bytes, bytes]:
        """Derive Key Block Encryption and Authentication Keys"""
        return (
            _tools.xor(self.kbpk, b"\x45" * len(self.kbpk)),  # Encryption Key
            _tools.xor(self.kbpk, b"\x4D" * len(self.kbpk)),  # Authentication Key
        )

    def _c_generate_mac(self, kbak: bytes, header: str, key_data: bytes) -> bytes:
        """Generate MAC using KBAK"""
        return _mac.generate_cbc_mac(kbak, header.encode("ascii") + key_data, 1, 4)

    _wrap_dispatch: _typing.Dict[
        str, _typing.Callable[["KeyBlock", str, bytes, int], str]
    ] = {
        "A": _c_wrap,
        "B": _b_wrap,
        "C": _c_wrap,
    }

    _unwrap_dispatch: _typing.Dict[
        str, _typing.Callable[["KeyBlock", str, bytes, bytes], bytes]
    ] = {
        "A": _c_unwrap,
        "B": _b_unwrap,
        "C": _c_unwrap,
    }


def wrap(
    kbpk: bytes,
    header: _typing.Union[Header, str],
    key: bytes,
    masked_key_len: _typing.Optional[int] = None,
) -> str:
    r"""Wrap key into a TR-31 key block version A, B or C.

    Parameters
    ----------
    kbpk : bytes
        Key Block Protection Key.
        The length of the KBPK must equal or greater than the key to be protected.
        Must be 8, 16 or 24 DES key for versions A and C.
        Must be 16 or 24 DES key for versions B.
        Must be 16, 24 or 32 AES key for version D.
    header : Header or str
        TR-31 key block header either in TR-31 string format or
        as a Header class.
        A full TR-31 key block in string format can be provided
        to extract header from.
    key : bytes
        A key to be wrapped.
        Must be a valid DES key for versions A, B and C.
        Must be a valid AES key for version D.
    masked_key_len : int, optional
        Desired key length in bytes to mask true key length.
        Must be 8, 16 or 24 for versions A, B and C (DES).
        Must be 16, 24 or 32 for version D (AES).
        Defaults to max key size.

    Returns
    -------
    key_block : str
        Key formatted in a TR-31 key block and encrypted
        under the KBPK.

    Raises
    ------
    KeyBlockError
    HeaderError

    Examples
    --------
    >>> import psec
    >>> psec.tr31.wrap(
    ...     kbpk=b"\xAB" * 16,
    ...     header="B0096P0TE00N0000",
    ...     key=b"\xCD" * 16)  # doctest: +SKIP
    'B0096P0TE00N0000471D4FBE35E5865BDE20DBF4C15503161F55D681170BF8DD14D01B6822EF8550CB67C569DE8AC048'
    """
    return KeyBlock(kbpk, header).wrap(key, masked_key_len)


def unwrap(kbpk: bytes, key_block: str) -> _typing.Tuple[Header, bytes]:
    r"""Unwrap key from a TR-31 key block version A, B or C.

    Parameters
    ----------
    kbpk : bytes
        Key Block Protection Key.
        The length of the KBPK must equal or greater than the key to be protected.
        Must be 8, 16 or 24 DES key for versions A and C.
        Must be 16 or 24 DES key for versions B.
        Must be 16, 24 or 32 AES key for version D.
    key_block : str
        A TR-31 key block.

    Returns
    -------
    header : Header
        TR-31 key block header.
    key : bytes
        Unwrapped key.
        A DES key for versions A, B and C.
        An AES key for version D.

    Raises
    ------
    KeyBlockError
    HeaderError

    Examples
    --------
    >>> import psec
    >>> header, key = psec.tr31.unwrap(
    ...     kbpk=b"\xAB" * 16,
    ...     key_block="B0096P0TE00N0000471D4FBE35E5865BDE20DBF4C15503161F55D681170BF8DD14D01B6822EF8550CB67C569DE8AC048")
    >>> key
    b'\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd'
    >>> header.version_id
    'B'
    >>> header.key_usage
    'P0'
    >>> header.algorithm
    'T'
    >>> header.mode_of_use
    'E'
    >>> header.version_num
    '00'
    >>> header.exportability
    'N'
    """
    kb = KeyBlock(kbpk)
    return kb.header, kb.unwrap(key_block)
