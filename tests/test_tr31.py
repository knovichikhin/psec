import pytest
from psec import tr31


def test_header_load() -> None:
    h = tr31.TR31Header()
    assert h.load("B0000P0TE00N0000xxxxxxxx") == 16
    assert h.version_id == "B"
    assert h.key_usage == "P0"
    assert h.algorithm == "T"
    assert h.mode_of_use == "E"
    assert h.exportability == "N"
    assert len(h.blocks) == 0
    assert str(h) == "B0016P0TE00N0000"


def test_header_load_optional() -> None:
    h = tr31.TR31Header()
    assert h.load("B0000P0TE00N0100KS1800604B120F9292800000xxxxxxxx") == 40
    assert h.version_id == "B"
    assert h.key_usage == "P0"
    assert h.algorithm == "T"
    assert h.mode_of_use == "E"
    assert h.exportability == "N"
    assert len(h.blocks) == 1
    assert h.blocks["KS"] == "00604B120F9292800000"
    assert str(h) == "B0040P0TE00N0100KS1800604B120F9292800000"


def test_header_load_optional_with_bad_count() -> None:
    """One optional block is present, but number of optional blocks is 00"""
    h = tr31.TR31Header()
    assert h.load("B0000P0TE00N0000KS1800604B120F9292800000") == 16
    assert h.version_id == "B"
    assert h.key_usage == "P0"
    assert h.algorithm == "T"
    assert h.mode_of_use == "E"
    assert h.exportability == "N"
    assert len(h.blocks) == 0
    assert str(h) == "B0016P0TE00N0000"


def test_header_load_optional_padded() -> None:
    """Two optional blocks are present, one is pad block"""
    h = tr31.TR31Header()
    assert h.load("B0000P0TE00N0200KS1200604B120F9292PB0600") == 40
    assert h.version_id == "B"
    assert h.key_usage == "P0"
    assert h.algorithm == "T"
    assert h.mode_of_use == "E"
    assert h.exportability == "N"
    assert len(h.blocks) == 1
    assert h.blocks["KS"] == "00604B120F9292"
    assert str(h) == "B0040P0TE00N0200KS1200604B120F9292PB0600"


def test_header_load_optional_256() -> None:
    """An optional block with length >255"""
    h = tr31.TR31Header()
    assert h.load("B0000P0TE00N0200KS0002010A" + "P" * 256 + "PB0600") == 288
    assert h.version_id == "B"
    assert h.key_usage == "P0"
    assert h.algorithm == "T"
    assert h.mode_of_use == "E"
    assert h.exportability == "N"
    assert len(h.blocks) == 1
    assert h.blocks["KS"] == "P" * 256
    assert str(h) == "B0288P0TE00N0200KS0002010A" + "P" * 256 + "PB0600"


def test_header_load_optional_extended_length() -> None:
    """An optional block with extended length just because"""
    h = tr31.TR31Header()
    assert h.load("B0000P0TE00N0200KS00011600604B120F9292PB0A000000") == 48
    assert h.version_id == "B"
    assert h.key_usage == "P0"
    assert h.algorithm == "T"
    assert h.mode_of_use == "E"
    assert h.exportability == "N"
    assert len(h.blocks) == 1
    assert h.blocks["KS"] == "00604B120F9292"
    assert str(h) == "B0040P0TE00N0200KS1200604B120F9292PB0600"


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

    def sanity_check(kbpk: bytes, key: bytes, header: tr31.TR31Header) -> None:
        kb = tr31.TR31KeyBlock(kbpk, header)
        raw_kb = kb.wrap(key)

        assert key == kb.unwrap(raw_kb)
        assert key == tr31.TR31KeyBlock(kbpk).unwrap(raw_kb)

    header = tr31.TR31Header(version_id, "P0", "T", "E", "00", "N")
    sanity_check(kbpk, key, header)


# fmt: off
@pytest.mark.parametrize(
    ["kbpk", "key", "tr31kb"],
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
def test_kb_known_values(kbpk: str, key: str, tr31kb: str) -> None:
    """Test against known values from 3rd parties"""
    kbpk_b = bytes.fromhex(kbpk)
    key_b = bytes.fromhex(key)
    assert key_b == tr31.TR31KeyBlock(kbpk_b).unwrap(tr31kb)
