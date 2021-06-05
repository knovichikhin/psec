import pytest
from psec import tr31


def test_header_load() -> None:
    h = tr31.Header()
    assert h.load("B0000P0TE00N0000xxxxxxxx") == 16
    assert h.version_id == "B"
    assert h.key_usage == "P0"
    assert h.algorithm == "T"
    assert h.mode_of_use == "E"
    assert h.exportability == "N"
    assert h.reserved == "00"
    assert len(h.blocks) == 0
    assert str(h) == "B0016P0TE00N0000"


def test_header_blocks_dict() -> None:
    h = tr31.Header("B", "P0", "T", "E")
    h.blocks["KS"] = "ABCD"
    assert len(h.blocks) == 1
    assert h.blocks["KS"] == "ABCD"
    assert ("KS" in h.blocks) is True
    assert repr(h.blocks) == "{'KS': 'ABCD'}"

    del h.blocks["KS"]
    assert len(h.blocks) == 0
    with pytest.raises(KeyError):
        h.blocks["KS"]
    assert ("KS" in h.blocks) is False
    assert repr(h.blocks) == "{}"


def test_header_load_optional() -> None:
    h = tr31.Header()
    assert h.load("B0000P0TE00N0100KS1800604B120F9292800000xxxxxxxx") == 40
    assert h.version_id == "B"
    assert h.key_usage == "P0"
    assert h.algorithm == "T"
    assert h.mode_of_use == "E"
    assert h.exportability == "N"
    assert h.reserved == "00"
    assert len(h.blocks) == 1
    assert h.blocks["KS"] == "00604B120F9292800000"
    assert str(h) == "B0040P0TE00N0100KS1800604B120F9292800000"


def test_header_load_optional_with_bad_count() -> None:
    """One optional block is present, but number of optional blocks is 00"""
    h = tr31.Header()
    assert h.load("B0000P0TE00N0000KS1800604B120F9292800000") == 16
    assert h.version_id == "B"
    assert h.key_usage == "P0"
    assert h.algorithm == "T"
    assert h.mode_of_use == "E"
    assert h.exportability == "N"
    assert h.reserved == "00"
    assert len(h.blocks) == 0
    assert str(h) == "B0016P0TE00N0000"


def test_header_load_optional_padded() -> None:
    """Two optional blocks are present, one is pad block"""
    h = tr31.Header()
    assert h.load("B0000P0TE00N0200KS1200604B120F9292PB0600") == 40
    assert h.version_id == "B"
    assert h.key_usage == "P0"
    assert h.algorithm == "T"
    assert h.mode_of_use == "E"
    assert h.exportability == "N"
    assert h.reserved == "00"
    assert len(h.blocks) == 1
    assert h.blocks["KS"] == "00604B120F9292"
    assert str(h) == "B0040P0TE00N0200KS1200604B120F9292PB0600"


def test_header_load_optional_256() -> None:
    """An optional block with length >255"""
    h = tr31.Header()
    assert h.load("B0000P0TE00N0200KS0002010A" + "P" * 256 + "PB0600") == 288
    assert h.version_id == "B"
    assert h.key_usage == "P0"
    assert h.algorithm == "T"
    assert h.mode_of_use == "E"
    assert h.exportability == "N"
    assert h.reserved == "00"
    assert len(h.blocks) == 1
    assert h.blocks["KS"] == "P" * 256
    assert str(h) == "B0288P0TE00N0200KS0002010A" + "P" * 256 + "PB0600"


def test_header_load_optional_extended_length() -> None:
    """An optional block with extended length just because"""
    h = tr31.Header()
    assert h.load("B0000P0TE00N0200KS00011600604B120F9292PB0A000000") == 48
    assert h.version_id == "B"
    assert h.key_usage == "P0"
    assert h.algorithm == "T"
    assert h.mode_of_use == "E"
    assert h.exportability == "N"
    assert h.reserved == "00"
    assert len(h.blocks) == 1
    assert h.blocks["KS"] == "00604B120F9292"
    assert str(h) == "B0040P0TE00N0200KS1200604B120F9292PB0600"


def test_header_load_optional_multiple() -> None:
    """Load multiple optional blocks"""
    h = tr31.Header()
    assert h.load("B0000P0TE00N0400KS1800604B120F9292800000T104T20600PB0600") == 56
    assert h.version_id == "B"
    assert h.key_usage == "P0"
    assert h.algorithm == "T"
    assert h.mode_of_use == "E"
    assert h.exportability == "N"
    assert h.reserved == "00"
    assert len(h.blocks) == 3
    assert h.blocks["KS"] == "00604B120F9292800000"
    assert h.blocks["T1"] == ""
    assert h.blocks["T2"] == "00"
    assert str(h) == "B0056P0TE00N0400KS1800604B120F9292800000T104T20600PB0600"


def test_header_load_optional_reset() -> None:
    """Make sure optional blocks are reset between loads"""
    h = tr31.Header()
    assert h.load("B0000P0TE00N0400KS1800604B120F9292800000T104T20600PB0600") == 56
    assert h.load("B0000P0TE00N0000") == 16
    assert h.version_id == "B"
    assert h.key_usage == "P0"
    assert h.algorithm == "T"
    assert h.mode_of_use == "E"
    assert h.exportability == "N"
    assert h.reserved == "00"
    assert len(h.blocks) == 0
    assert str(h) == "B0016P0TE00N0000"


# fmt: off
@pytest.mark.parametrize(
    ["header", "error"],
    [
        ("B0000P0TE00N0100",         "Block ID () is malformed."),
        ("B0000P0TE00N0100K",        "Block ID (K) is malformed."),
        ("B0000P0TE00N0100KS",       "Block KS length () is malformed. Expecting 2 hexchars."),
        ("B0000P0TE00N0100KS1",      "Block KS length (1) is malformed. Expecting 2 hexchars."),
        ("B0000P0TE00N0100KS1Y",     "Block KS length (1Y) is malformed. Expecting 2 hexchars."),
        ("B0000P0TE00N0100KS02",     "Block KS length does not include block ID and length."),
        ("B0000P0TE00N0100KS071",    "Block KS data is malformed. Received 1/3. Block data: '1'"),
        ("B0000P0TE00N0100KS00",     "Block KS length of length () is malformed. Expecting 2 hexchars."),
        ("B0000P0TE00N0100KS001",    "Block KS length of length (1) is malformed. Expecting 2 hexchars."),
        ("B0000P0TE00N0100KS001S",   "Block KS length of length (1S) is malformed. Expecting 2 hexchars."),
        ("B0000P0TE00N0100KS0000",   "Block KS length of length must not be 0."),
        ("B0000P0TE00N0100KS0001",   "Block KS length () is malformed. Expecting 2 hexchars."),
        ("B0000P0TE00N0100KS00010",  "Block KS length (0) is malformed. Expecting 2 hexchars."),
        ("B0000P0TE00N0100KS00010H", "Block KS length (0H) is malformed. Expecting 2 hexchars."),
        ("B0000P0TE00N0100KS000101", "Block KS length does not include block ID and length."),
        ("B0000P0TE00N0100KS0001FF", "Block KS data is malformed. Received 0/247. Block data: ''"),
        ("B0000P0TE00N0200KS07000T",     "Block ID (T) is malformed."),
        ("B0000P0TE00N0200KS0600TT",     "Block TT length () is malformed. Expecting 2 hexchars."),
        ("B0000P0TE00N0200KS050TT1",     "Block TT length (1) is malformed. Expecting 2 hexchars."),
        ("B0000P0TE00N0200KS04TT1X",     "Block TT length (1X) is malformed. Expecting 2 hexchars."),
        ("B0000P0TE00N0200KS04TT03",     "Block TT length does not include block ID and length."),
        ("B0000P0TE00N0200KS04TT05",     "Block TT data is malformed. Received 0/1. Block data: ''"),
        ("B0000P0TE00N0200KS04TT00",     "Block TT length of length () is malformed. Expecting 2 hexchars."),
        ("B0000P0TE00N0200KS04TT001",    "Block TT length of length (1) is malformed. Expecting 2 hexchars."),
        ("B0000P0TE00N0200KS04TT001S",   "Block TT length of length (1S) is malformed. Expecting 2 hexchars."),
        ("B0000P0TE00N0200KS04TT0000",   "Block TT length of length must not be 0."),
        ("B0000P0TE00N0200KS04TT0001",   "Block TT length () is malformed. Expecting 2 hexchars."),
        ("B0000P0TE00N0200KS04TT00010",  "Block TT length (0) is malformed. Expecting 2 hexchars."),
        ("B0000P0TE00N0200KS04TT00010H", "Block TT length (0H) is malformed. Expecting 2 hexchars."),
        ("B0000P0TE00N0200KS04TT000101", "Block TT length does not include block ID and length."),
        ("B0000P0TE00N0200KS04TT00011F", "Block TT data is malformed. Received 0/23. Block data: ''"),
        ("B0000P0TE00N0100**04",         "Block ID (**) is invalid. Expecting 2 alphanumeric characters."),
        ("B0000P0TE00N0200KS0600??04",   "Block ID (??) is invalid. Expecting 2 alphanumeric characters."),
        ("B0000P0TE00N0100KS05\x03",     "Block KS data is invalid. Expecting ASCII printable characters. Data: '\x03'"),
        ("B0000P0TE00N0200KS04TT05\xFF", "Block TT data is invalid. Expecting ASCII printable characters. Data: '\xFF'"),
    ],
)
# fmt: on
def test_header_block_load_exceptions(header: str, error: str) -> None:
    """Make sure optional blocks handle input validation"""
    h = tr31.Header()
    with pytest.raises(tr31.HeaderError) as e:
        h.load(header)
    assert e.value.args[0] == error


def test_header_block_dump_exception_block_too_large() -> None:
    """Make sure optional blocks handle a single large block
    that's too large to fit into a key block."""
    h = tr31.Header()
    h.blocks["LG"] = "P" * 70000  # > unsigned int 16
    with pytest.raises(tr31.HeaderError) as e:
        _ = h.dump(16)
    assert e.value.args[0] == "Block LG length (70000) is too long."


def test_header_block_dump_exception_too_many_blocks() -> None:
    """Make sure optional blocks handle a limit of 99 blocks
    without a pad block embedded."""
    h = tr31.Header()
    for i in range(0, 100):
        h.blocks[str(i).zfill(2)] = "PPPP"  # each block is multiple of 8
    with pytest.raises(tr31.HeaderError) as e:
        _ = h.dump(16)
    assert e.value.args[0] == "Number of blocks (100) exceeds limit of 99."


def test_header_block_dump_exception_too_many_blocks_pb() -> None:
    """Make sure optional blocks handle a limit of 99 blocks
    with a pad block embedded."""
    h = tr31.Header()
    for i in range(0, 99):
        h.blocks[str(i).zfill(2)] = "PP"
    with pytest.raises(tr31.HeaderError) as e:
        _ = h.dump(16)
    assert e.value.args[0] == "Number of blocks (100) exceeds limit of 99."


# fmt: off
@pytest.mark.parametrize(
    ["header", "error"],
    [
        ("_0000P0TE00N0000", "Header must be ASCII alphanumeric. Header: '_0000P0TE00N0000'"),
        ("",                 "Header length (0) must be >=16. Header: ''"),
        ("B0000",            "Header length (5) must be >=16. Header: 'B0000'"),
        ("B0000P0TE00N0X00", "Number of blocks (0X) is invalid. Expecting 2 digits."),
    ],
)
# fmt: on
def test_header_load_exceptions(header: str, error: str) -> None:
    """Make sure header handle load method validation"""
    h = tr31.Header()
    with pytest.raises(tr31.HeaderError) as e:
        h.load(header)
    assert e.value.args[0] == error


# fmt: off
@pytest.mark.parametrize(
    ["version_id", "key_usage", "algorithm", "mode_of_use", "version_num", "exportability", "error"],
    [
        ("_",  "P0",  "T",  "E",  "00",  "N",  "Version ID (_) is not supported."),
        ("B0", "P0",  "T",  "E",  "00",  "N",  "Version ID (B0) is not supported."),
        ("",   "P0",  "T",  "E",  "00",  "N",  "Version ID () is not supported."),
        ("B",  "P_",  "T",  "E",  "00",  "N",  "Key usage (P_) is invalid."),
        ("B",  "P",   "T",  "E",  "00",  "N",  "Key usage (P) is invalid."),
        ("B",  "P00", "T",  "E",  "00",  "N",  "Key usage (P00) is invalid."),
        ("B",  "P0",  "",   "E",  "00",  "N",  "Algorithm () is invalid."),
        ("B",  "P0",  "_",  "E",  "00",  "N",  "Algorithm (_) is invalid."),
        ("B",  "P0",  "T0", "E",  "00",  "N",  "Algorithm (T0) is invalid."),
        ("B",  "P0",  "T",  "_",  "00",  "N",  "Mode of use (_) is invalid."),
        ("B",  "P0",  "T",  "",   "00",  "N",  "Mode of use () is invalid."),
        ("B",  "P0",  "T",  "EE", "00",  "N",  "Mode of use (EE) is invalid."),
        ("B",  "P0",  "T",  "E",  "0",   "N",  "Version number (0) is invalid."),
        ("B",  "P0",  "T",  "E",  "000", "N",  "Version number (000) is invalid."),
        ("B",  "P0",  "T",  "E",  "0_",  "N",  "Version number (0_) is invalid."),
        ("B",  "P0",  "T",  "E",  "00",  "",   "Exportability () is invalid."),
        ("B",  "P0",  "T",  "E",  "00",  "NN", "Exportability (NN) is invalid."),
        ("B",  "P0",  "T",  "E",  "00",  "_",  "Exportability (_) is invalid."),
    ],
)
# fmt: on
def test_header_attributes_exceptions(
    version_id: str,
    key_usage: str,
    algorithm: str,
    mode_of_use: str,
    version_num: str,
    exportability: str,
    error: str,
) -> None:
    """Make sure header handle attribute validation"""
    with pytest.raises(tr31.HeaderError) as e:
        _ = tr31.Header(
            version_id, key_usage, algorithm, mode_of_use, version_num, exportability
        )
    assert e.value.args[0] == error


# fmt: off
@pytest.mark.parametrize(
    ["version_id", "key_len", "error"],
    [
        ("A", 7, "Key length (7) must be 8, 16, 24 for key block version A."),
        ("B", 7, "Key length (7) must be 8, 16, 24 for key block version B."),
        ("C", 7, "Key length (7) must be 8, 16, 24 for key block version C."),
        ("D", 7, "Key length (7) must be 16, 24, 32 for key block version D."),
    ],
)
# fmt: on
def test_header_dump_exceptions(version_id: str, key_len: int, error: str) -> None:
    """Make sure header dump method handle input validation"""
    h = tr31.Header(version_id)
    with pytest.raises(tr31.HeaderError) as e:
        h.dump(key_len)
    assert e.value.args[0] == error


def test_header_dump_exception_kb_too_large() -> None:
    """Make sure header dump method handle input validation: header size too large"""
    h = tr31.Header()
    h.blocks["T0"] = "P" * 9990
    with pytest.raises(tr31.HeaderError) as e:
        _ = h.dump(16)
    assert e.value.args[0] == "Total key block length (10080) exceeds limit of 9992."


# fmt: off
@pytest.mark.parametrize(
    ["version_id", "kbpk", "key"],
    [
        ("A", b"A"*8+b"B"*8+b"C"*8, b"1"*8+b"2"*8+b"3"*8),
        ("A", b"A"*8+b"B"*8+b"C"*8, b"1"*8+b"2"*8),
        ("A", b"A"*8+b"B"*8+b"C"*8, b"1"*8),
        ("A", b"A"*8+b"B"*8,        b"1"*8+b"2"*8),
        ("A", b"A"*8+b"B"*8,        b"1"*8),
        ("A", b"A"*8,               b"1"*8),
        ("B", b"A"*8+b"B"*8+b"C"*8, b"1"*8+b"2"*8+b"3"*8),
        ("B", b"A"*8+b"B"*8+b"C"*8, b"1"*8+b"2"*8),
        ("B", b"A"*8+b"B"*8+b"C"*8, b"1"*8),
        ("B", b"A"*8+b"B"*8,        b"1"*8+b"2"*8),
        ("B", b"A"*8+b"B"*8,        b"1"*8),
        ("C", b"A"*8+b"B"*8+b"C"*8, b"1"*8+b"2"*8+b"3"*8),
        ("C", b"A"*8+b"B"*8+b"C"*8, b"1"*8+b"2"*8),
        ("C", b"A"*8+b"B"*8+b"C"*8, b"1"*8),
        ("C", b"A"*8+b"B"*8,        b"1"*8+b"2"*8),
        ("C", b"A"*8+b"B"*8,        b"1"*8),
        ("C", b"A"*8,               b"1"*8),
    ],
)
# fmt: on
def test_kb_sanity(version_id: str, kbpk: bytes, key: bytes) -> None:
    """Make sure that wrapping and then unwrapping produces original key"""

    def sanity_check(kbpk: bytes, key: bytes, header: tr31.Header) -> None:
        kb = tr31.KeyBlock(kbpk, header)
        raw_kb = kb.wrap(key)

        assert key == kb.unwrap(raw_kb)
        assert key == tr31.KeyBlock(kbpk).unwrap(raw_kb)

    header = tr31.Header(version_id, "P0", "T", "E", "00", "N")
    sanity_check(kbpk, key, header)


# fmt: off
@pytest.mark.parametrize(
    ["kbpk", "key", "kb"],
    [
        ("AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBB", "EEEEEEEEEEEEEEEE", "A0088M3TC00E000062C2C14D8785A01A9E8283525CA96F490D0CC6346FC7C2AC1E6FF354468910379AA5BBA6"),
        ("AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBB", "EEEEEEEEEEEEEEEE", "B0096M3TC00E0000B6CD513680EF255FC0DC590726FD0129A7CF6602E7F271631AB4EE7350642F11181AF4CC12F12FD9"),
        ("AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBB", "EEEEEEEEEEEEEEEE", "C0088M3TC00E0000A53CF172FE6562E7FDD5E6482E8925DA46F7FFE4D1BAD49EB33A9EDBB96A8A8D39F13A31"),
        ("AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBB", "CCCCCCCCCCCCCCCCDDDDDDDDDDDDDDDD", "A0088M3TC00E0000BE8AE894906D0B8F6FF555573A3907DC37FF13B12CE1CB8A97A97C8414AE1A8FF9183122"),
        ("AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBB", "CCCCCCCCCCCCCCCCDDDDDDDDDDDDDDDD", "B0096M3TC00E0000D578DACC2286C7D10F20DEA88799CA8A2F44E0CC21226A2158D5DC8FD5C78E621327DA956C678808"),
        ("AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBB", "CCCCCCCCCCCCCCCCDDDDDDDDDDDDDDDD", "C0088M3TC00E00009BC6306FC31891BF87B3148463627B1D68C603D9FAB9074E4A0D2E78D40B29905A826F5C"),
        ("AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBCCCCCCCCCCCCCCCC", "CCCCCCCCCCCCCCCCDDDDDDDDDDDDDDDD", "A0088M3TC00E000022BD7EC46BBE2A6A73389D1BA6DB63120B386F912839F4679C0523399E4D8D0F1D9A356E"),
        ("AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBCCCCCCCCCCCCCCCC", "CCCCCCCCCCCCCCCCDDDDDDDDDDDDDDDD", "B0096M3TC00E0000C7C6FE86A5DE769C20DCA238C52341378B484D544A9764D43963C3B2824AE56C2D07A565DD3AB342"),
        ("AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBCCCCCCCCCCCCCCCC", "CCCCCCCCCCCCCCCCDDDDDDDDDDDDDDDD", "C0088M3TC00E000091FA4978279FD9C218BDCBE9CC62F11A182F828406B67AC61B5573748FCF348FD59FA93A"),
        ("89E88CF7931444F334BD7547FC3F380C", "F039121BEC83D26B169BDCD5B22AAF8F", "A0072P0TE00E0000F5161ED902807AF26F1D62263644BD24192FDB3193C730301CEE8701"),
        ("DD7515F2BFC17F85CE48F3CA25CB21F6", "3F419E1CB7079442AA37474C2EFBF8B8", "B0080P0TE00E000094B420079CC80BA3461F86FE26EFC4A3B8E4FA4C5F5341176EED7B727B8A248E"),
        ("B8ED59E0A279A295E9F5ED7944FD06B9", "EDB380DD340BC2620247D445F5B8D678", "C0096B0TX12S0100KS1800604B120F9292800000BFB9B689CB567E66FC3FEE5AD5F52161FC6545B9D60989015D02155C"),
        ("1D22BF32387C600AD97F9B97A51311AC", "E8BC63E5479455E26577F715D587FE68", "B0104B0TX12S0100KS1800604B120F9292800000BB68BE8680A400D9191AD4ECE45B6E6C0D21C4738A52190E248719E24B433627"),
        ("89E88CF7931444F334BD7547FC3F380C", "F039121BEC83D26B169BDCD5B22AAF8F", "A0088P0TE00E00007DD4DD9566DC0E2F956DCAC0FDE9153159539373E9D82D3CD4AFD305A7EF1BA67FE03712"),
        ("89E88CF7931444F334BD7547FC3F380C", "F039121BEC83D26B169BDCD5B22AAF8F", "B0120P0TE12E0100KS1800604B120F9292800000E6E28F097CB0350B2EB2DF520947F779FA34D9759CEE7E0DEEACF8353DB778D47FA4EC20DA3A9754"),
        ("B8ED59E0A279A295E9F5ED7944FD06B9", "F039121BEC83D26B169BDCD5B22AAF8F", "A0112P0TE12E0200KS1400604B120F929280PB047A1BB737854CD7AF58A8A1E4506A942277EDA76EBA6BA228AF62ADDA3AD8799E8B2C8CD7"),
        ("89E88CF7931444F334BD7547FC3F380C", "F039121BEC83D26B169BDCD5B22AAF8F", "A0088P0TE00E00007DD4DD9566DC0E2F956DCAC0FDE91531723FD88F18DE071A57189B4D3C483341ED79F4E0"),
    ],
)
# fmt: on
def test_kb_known_values(kbpk: str, key: str, kb: str) -> None:
    """Test against known values from 3rd parties"""
    kbpk_b = bytes.fromhex(kbpk)
    key_b = bytes.fromhex(key)
    assert key_b == tr31.KeyBlock(kbpk_b).unwrap(kb)


# fmt: off
@pytest.mark.parametrize(
    ["version_id", "kbpk_len", "key_len", "masked_key_len", "kb_len"],
    [
        ("A", 24, 24, 24,   88),
        ("A", 24, 16, 24,   88),
        ("A", 24,  8, 24,   88),
        ("A", 24, 24, None, 88),
        ("A", 24, 16, None, 88),
        ("A", 24,  8, None, 88),
        ("A", 24, 16, 16,   72),
        ("A", 24, 16,  8,   72),
        ("A", 24, 16,  0,   72),
        ("A", 24, 16, -8,   72),
        ("A", 24,  8,  8,   56),
        ("B", 24, 24, 24,   96),
        ("B", 24, 16, 24,   96),
        ("B", 24,  8, 24,   96),
        ("B", 24, 24, None, 96),
        ("B", 24, 16, None, 96),
        ("B", 24,  8, None, 96),
        ("B", 24, 16, 16,   80),
        ("B", 24, 16,  8,   80),
        ("B", 24, 16,  0,   80),
        ("B", 24, 16, -8,   80),
        ("B", 24,  8,  8,   64),
        ("C", 24, 24, 24,   88),
        ("C", 24, 16, 24,   88),
        ("C", 24,  8, 24,   88),
        ("C", 24, 24, None, 88),
        ("C", 24, 16, None, 88),
        ("C", 24,  8, None, 88),
        ("C", 24, 16, 16,   72),
        ("C", 24, 16,  8,   72),
        ("C", 24, 16,  0,   72),
        ("C", 24, 16, -8,   72),
        ("C", 24,  8,  8,   56),
    ],
)
# fmt: on
def test_kb_masking_key_length(
    version_id: str, kbpk_len: int, key_len: int, masked_key_len: int, kb_len: int
) -> None:
    """Test KB key masking"""
    kb = tr31.KeyBlock(b"E" * kbpk_len)
    kb.header.version_id = version_id
    kb_s = kb.wrap(b"F" * key_len, masked_key_len)
    assert len(kb_s) == kb_len
    assert kb_s[1:5] == str(kb_len).zfill(4)


def test_kb_wrap_unsupported_kb_version() -> None:
    """Test wrap with unsupported version ID"""
    with pytest.raises(tr31.KeyBlockError) as e:
        kb = tr31.KeyBlock(b"E" * 16)
        kb.header._version_id = "X"  # have to do this to bypass edit checks
        _ = kb.wrap(b"E" * 8)
    assert e.value.args[0] == "Key block version ID (X) is not supported."


# fmt: off
@pytest.mark.parametrize(
    ["version_id", "kbpk_len", "key_len", "error"],
    [
        ("A",  7, 24, "KBPK length (7) must be 1-key, 2-key or 3-key TDES."),
        ("B",  7, 24, "KBPK length (7) must be 2-key or 3-key TDES."),
        ("C",  7, 24, "KBPK length (7) must be 1-key, 2-key or 3-key TDES."),
        ("A", 16, 15, "Key length (15) must be 1-key, 2-key or 3-key TDES."),
        ("B", 16, 15, "Key length (15) must be 1-key, 2-key or 3-key TDES."),
        ("C", 16, 15, "Key length (15) must be 1-key, 2-key or 3-key TDES."),
        ("A", 16, 24, "Key length (24) must be less than or equal to KBPK (16)."),
        ("B", 16, 24, "Key length (24) must be less than or equal to KBPK (16)."),
        ("C", 16, 24, "Key length (24) must be less than or equal to KBPK (16)."),
    ],
)
# fmt: on
def test_kb_wrap_exceptions(
    version_id: str, kbpk_len: int, key_len: int, error: str
) -> None:
    """Test wrap exceptions"""
    with pytest.raises(tr31.KeyBlockError) as e:
        kb = tr31.KeyBlock(b"E" * kbpk_len)
        kb.header._version_id = version_id
        _ = kb.wrap(b"F" * key_len)
    assert e.value.args[0] == error


def test_kb_init_with_raw_header() -> None:
    """Initialize KB with raw TR-31 header string"""
    kb = tr31.KeyBlock(b"E" * 16, "B0000P0TE00N0000xxxxxxxx")
    assert kb.header.version_id == "B"
    assert kb.header.key_usage == "P0"
    assert kb.header.algorithm == "T"
    assert kb.header.mode_of_use == "E"
    assert kb.header.exportability == "N"
    assert kb.header.reserved == "00"
    assert len(kb.header.blocks) == 0
    assert str(kb) == "B0016P0TE00N0000"


def test_kb_init_with_raw_header_blocks() -> None:
    """Initialize KB with raw TR-31 header string"""
    kb = tr31.KeyBlock(b"E" * 16, "B0000P0TE00N0100KS1800604B120F9292800000xxxxxxxx")
    assert kb.header.version_id == "B"
    assert kb.header.key_usage == "P0"
    assert kb.header.algorithm == "T"
    assert kb.header.mode_of_use == "E"
    assert kb.header.exportability == "N"
    assert kb.header.reserved == "00"
    assert len(kb.header.blocks) == 1
    assert kb.header.blocks["KS"] == "00604B120F9292800000"
    assert str(kb) == "B0040P0TE00N0100KS1800604B120F9292800000"


# fmt: off
@pytest.mark.parametrize(
    ["kbpk_len", "kb", "error"],
    [
        (16, "B0040P0TE00N0000", "Key block header length (40) doesn't match input data length (16)."),
        (16, "BX040P0TE00N0000", "Key block header length (X040) is malformed. Expecting 4 digits."),
        (16, "A0087M3TC00E000062C2C14D8785A01A9E8283525CA96F490D0CC6346FC7C2AC1E6FF354468910379AA5BBA", "Key block length (87) must be multiple of 8."),

        (16, "A0088M3TC00E000062C2C14D8785A01A9E8283525CA96F490D0CC6346FC7C2AC1E6FF354468910379AA5BBAX", "Key block MAC must be valid hexchars. MAC: '9AA5BBAX'"),
        (16, "B0088M3TC00E000062C2C14D8785A01A9E8283525CA96F490D0CC6346FC7C2AC1E6FF354468910379AA5BBAX", "Key block MAC must be valid hexchars. MAC: '468910379AA5BBAX'"),
        (16, "C0088M3TC00E000062C2C14D8785A01A9E8283525CA96F490D0CC6346FC7C2AC1E6FF354468910379AA5BBAX", "Key block MAC must be valid hexchars. MAC: '9AA5BBAX'"),

        (16, "A0024M3TC00E0100TT04BBA6", "Key block MAC is malformed. Received 4/8. MAC: 'BBA6'"),
        (16, "B0024M3TC00E00009AA5BBA6", "Key block MAC is malformed. Received 8/16. MAC: '9AA5BBA6'"),
        (16, "C0024M3TC00E0100TT04BBA6", "Key block MAC is malformed. Received 4/8. MAC: 'BBA6'"),

        (16, "A0088M3TC00E000062C2C14D8785A01A9E8283525CA96F490D0CC6346FC7C2AC1E6FF3544689103X9AA5BBA6", "Encrypted key must be valid hexchars. Key data: '62C2C14D8785A01A9E8283525CA96F490D0CC6346FC7C2AC1E6FF3544689103X'"),
        (16, "B0088M3TC00E000062C2C14D8785A01A9E8283525CA96F490D0CC6346FC7C2AC1E6FF35X468910379AA5BBA6", "Encrypted key must be valid hexchars. Key data: '62C2C14D8785A01A9E8283525CA96F490D0CC6346FC7C2AC1E6FF35X'"),
        (16, "C0088M3TC00E000062C2C14D8785A01A9E8283525CA96F490D0CC6346FC7C2AC1E6FF3544689103X9AA5BBA6", "Encrypted key must be valid hexchars. Key data: '62C2C14D8785A01A9E8283525CA96F490D0CC6346FC7C2AC1E6FF3544689103X'"),

        (16, "A0024M3TC00E00009AA5BBA6", "Encrypted key is malformed. Key data: ''"),
        (16, "B0032M3TC00E0000FFFFFFFF9AA5BBA6", "Encrypted key is malformed. Key data: ''"),
        (16, "C0024M3TC00E00009AA5BBA6", "Encrypted key is malformed. Key data: ''"),

        (16, "A0056M3TC00E0000BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB9AA5BBA6", "Key block MAC doesn't match generated MAC."),
        (16, "B0064M3TC00E0000BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBFFFFFFFF9AA5BBA6", "Key block MAC doesn't match generated MAC."),
        (16, "C0056M3TC00E0000BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB9AA5BBA6", "Key block MAC doesn't match generated MAC."),

        (7,  "A0088M3TC00E000062C2C14D8785A01A9E8283525CA96F490D0CC6346FC7C2AC1E6FF354468910379AA5BBA6", "KBPK length (7) must be 1-key, 2-key or 3-key TDES."),
        (8,  "B0088M3TC00E000062C2C14D8785A01A9E8283525CA96F490D0CC6346FC7C2AC1E6FF354468910379AA5BBA6", "KBPK length (8) must be 2-key or 3-key TDES."),
        (7,  "C0088M3TC00E000062C2C14D8785A01A9E8283525CA96F490D0CC6346FC7C2AC1E6FF354468910379AA5BBA6", "KBPK length (7) must be 1-key, 2-key or 3-key TDES."),

        # These keys have length set to 0 bits. KBPK must be b"E"*16.
        (16, "A0056M3TC00E0000ABE3EB7813FD4031BCBAEC1FCAB750BB920E4863", "Decrypted key is invalid."),
        (16, "B0064M3TC00E000013F1B06566ECAE897A6DF8C7AA651FCEF9480447EEEC9933", "Decrypted key is invalid."),
        (16, "C0056M3TC00E0000629D73329F5F42D868B2EB1E4C52D1E191BC1D3C", "Decrypted key is invalid."),

        # These keys have length set to 128 bits where the key is 64 bits. KBPK must be b"E"*16.
        (16, "A0056M3TC00E0000EF14FD71CFCDCE0630AD5C1CDE0041DCF95CF1D0", "Decrypted key is malformed."),
        (16, "B0064M3TC00E00000398DC96A5DDB0EF61E26F8935173BD478DF9484050A672A", "Decrypted key is malformed."),
        (16, "C0056M3TC00E000001235EC22408B6CE866746FF992B8707FD7A26D2", "Decrypted key is malformed."),
    ],
)
# fmt: on
def test_kb_unwrap_exceptions(kbpk_len: int, kb: str, error: str) -> None:
    """Test unwrap exceptions"""
    with pytest.raises(tr31.KeyBlockError) as e:
        _ = tr31.KeyBlock(b"E" * kbpk_len).unwrap(kb)
    assert e.value.args[0] == error


def test_kb_unwrap_exceptions_unsupported_version() -> None:
    """Test unwrap exceptions"""
    kb = tr31.KeyBlock(b"E" * 16)
    # Have to cheat an explictly remove support for version B
    save_b = kb._unwrap_dispatch["B"]
    del kb._unwrap_dispatch["B"]
    with pytest.raises(tr31.KeyBlockError) as e:
        _ = kb.unwrap(
            "B0064M3TC00E00000398DC96A5DDB0EF61E26F8935173BD478DF9484050A672A"
        )
    kb._unwrap_dispatch["B"] = save_b
    assert e.value.args[0] == "Key block version ID (B) is not supported."

def test_wrap_unwrap_functions() -> None:
    kbpk = b"\xAB" * 16
    key = b"\xCD" * 16
    kb = tr31.wrap(kbpk, "B0096P0TE00N0000", key)
    h_out, key_out = tr31.unwrap(kbpk, kb)
    assert key == key_out
    assert h_out.version_id == "B"
    assert h_out.key_usage == "P0"
    assert h_out.algorithm == "T"
    assert h_out.mode_of_use == "E"
    assert h_out.version_num == "00"
    assert h_out.exportability == "N"
    assert h_out.reserved == "00"
    assert len(h_out.blocks) == 0
