import pytest
from psec import pinblock

import secrets as _secrets
from os import urandom as _urandom


# fmt: off
@pytest.mark.parametrize(
    ["pin", "pan", "error"],
    [
        ("123", "55555555555555", "PIN must be between 4 and 12 digits long"),
        ("1234567890123", "55555555555555", "PIN must be between 4 and 12 digits long"),
        ("123A", "55555555555555", "PIN must be between 4 and 12 digits long"),
        ("1234", "555555555555", "PAN must be at least 13 digits long"),
        ("1234", "5555555555555A", "PAN must be at least 13 digits long"),
    ],
)
# fmt: on
def test_encode_pinblock_iso_0_exception(pin: str, pan: str, error: str) -> None:
    with pytest.raises(
        ValueError,
        match=error,
    ):
        pinblock.encode_pinblock_iso_0(pin, pan)


@pytest.mark.parametrize(
    ["pin", "pan", "pin_block"],
    [
        ("1234", "5555555551234567", "041261AAAAEDCBA9"),
        ("123456789012", "5555555551234567", "0C1261032D8226A9"),
    ],
)
def test_encode_pinblock_iso_0(pin: str, pan: str, pin_block: str) -> None:
    assert pin_block == pinblock.encode_pinblock_iso_0(pin, pan).hex().upper()


# fmt: off
@pytest.mark.parametrize(
    ["pin", "error"],
    [
        ("123", "PIN must be between 4 and 12 digits long"),
        ("1234567890123", "PIN must be between 4 and 12 digits long"),
        ("123A", "PIN must be between 4 and 12 digits long"),
    ],
)
# fmt: on
def test_encode_pinblock_iso_2_exception(pin: str, error: str) -> None:
    with pytest.raises(
        ValueError,
        match=error,
    ):
        pinblock.encode_pinblock_iso_2(pin)


@pytest.mark.parametrize(
    ["pin", "pin_block"],
    [
        ("1234", "241234FFFFFFFFFF"),
        ("123456789", "29123456789FFFFF"),
        ("1234567890", "2A1234567890FFFF"),
        ("123456789012", "2C123456789012FF"),
    ],
)
def test_encode_pinblock_iso_2(pin: str, pin_block: str) -> None:
    assert pin_block == pinblock.encode_pinblock_iso_2(pin).hex().upper()


# fmt: off
@pytest.mark.parametrize(
    ["pin", "pan", "error"],
    [
        ("123", "55555555555555", "PIN must be between 4 and 12 digits long"),
        ("1234567890123", "55555555555555", "PIN must be between 4 and 12 digits long"),
        ("123A", "55555555555555", "PIN must be between 4 and 12 digits long"),
        ("1234", "555555555555", "PAN must be at least 13 digits long"),
        ("1234", "5555555555555A", "PAN must be at least 13 digits long"),
    ],
)
# fmt: on
def test_encode_pinblock_iso_3_exception(pin: str, pan: str, error: str) -> None:
    with pytest.raises(
        ValueError,
        match=error,
    ):
        pinblock.encode_pinblock_iso_3(pin, pan)


@pytest.mark.parametrize(
    ["pin", "pan", "pin_block"],
    [
        ("1234", "5555555551234567", "341261"),
        ("123456789012", "5555555551234567", "3C1261032D8226"),
    ],
)
def test_encode_pinblock_iso_3(pin: str, pan: str, pin_block: str) -> None:
    assert (
        pin_block
        == pinblock.encode_pinblock_iso_3(pin, pan).hex().upper()[: 2 + len(pin)]
    )


@pytest.mark.parametrize(
    ["pin", "error"],
    [
        ("123", "PIN must be between 4 and 12 digits long"),
        ("1234567890123", "PIN must be between 4 and 12 digits long"),
    ],
)
def test_encode_pin_field_iso_4_exception(pin: str, error: str) -> None:
    with pytest.raises(
        ValueError,
        match=error,
    ):
        pinblock.encode_pin_field_iso_4(pin)


@pytest.mark.parametrize(
    ["pin", "pin_field"],
    [
        ("1234", "441234AAAAAAAAAA"),
    ],
)
def test_encode_pin_field_iso_4(pin: str, pin_field: str) -> None:
    assert pin_field == pinblock.encode_pin_field_iso_4(pin).hex().upper()[:16]


@pytest.mark.parametrize(
    ["pan", "error"],
    [
        ("", "PAN must be between 1 and 19 digits long."),
        ("12345678901234567890", "PAN must be between 1 and 19 digits long."),
    ],
)
# fmt: on
def test_encode_pan_field_iso_4_exception(pan: str, error: str) -> None:
    with pytest.raises(
        ValueError,
        match=error,
    ):
        pinblock.encode_pan_field_iso_4(pan)


@pytest.mark.parametrize(
    ["pan", "pan_field"],
    [
        ("112233445566778899", "61122334455667788990000000000000"),
    ],
)
# fmt: on
def test_encode_pan_field_iso_4(pan: str, pan_field: str) -> None:
    assert pan_field == pinblock.encode_pan_field_iso_4(pan).hex().upper()


# fmt: off
@pytest.mark.parametrize(
    ["key", "pin", "pan", "error"],
    [
        (b"1" * 16, "123", "55555555555555", "PIN must be between 4 and 12 digits long"),
        (b"1" * 16, "1234567890123", "55555555555555", "PIN must be between 4 and 12 digits long"),
        (b"1" * 16, "123A", "55555555555555", "PIN must be between 4 and 12 digits long"),
        (b"1" * 16, "1234", "", "PAN must be between 1 and 19 digits long."),
        (b"1" * 16, "1234", "555555555555555555555", "PAN must be between 1 and 19 digits long."),
        (b"1" * 16, "1234", "5555555555555A", "PAN must be between 1 and 19 digits long."),
    ],
)
# fmt: on
def test_encipher_pinblock_iso_4_exception(
    key: bytes, pin: str, pan: str, error: str
) -> None:
    with pytest.raises(
        ValueError,
        match=error,
    ):
        pinblock.encipher_pinblock_iso_4(key, pin, pan)


# deterministic
@pytest.mark.parametrize(
    ["key", "pin", "pan", "pin_block"],
    [
        (
            bytes.fromhex("00112233445566778899AABBCCDDEEFF"),
            "1234",
            "1234567890123456789",
            "28B41FDDD29B743E93124BD8E32D921E",
        ),
    ],
)
def test_encipher_pinblock_iso_4_det(
    key: bytes, pin: str, pan: str, pin_block: str
) -> None:
    pinblock._urandom = lambda n: bytes.fromhex("FF") * n
    assert pin_block == pinblock.encipher_pinblock_iso_4(key, pin, pan).hex().upper()


# non deterministic
def test_encipher_decipher_pinblock_iso_4_non_det() -> None:
    pin_len = _secrets.choice(range(4, 12))
    pin_range_start = 10 ** (pin_len - 1)
    pin_range_end = (10**pin_len) - 1
    pin = str(_secrets.choice(range(pin_range_start, pin_range_end)))
    pan = "12334567890123456"
    key_lens = [16, 24, 32]
    key_len = _secrets.choice(key_lens)
    key = _urandom(key_len)
    pin_block = pinblock.encipher_pinblock_iso_4(key, pin, pan)
    pin_calc = pinblock.decipher_pinblock_iso_4(key, pin_block, pan)

    assert pin == pin_calc


# fmt: off
@pytest.mark.parametrize(
    ["pin_block", "pan", "error"],
    [
        (bytes.fromhex("241261AAAAEDCBA9"), "5555555551234567", "PIN block is not ISO format 0: control field `2`"),
        (bytes.fromhex("041261AAAAEDCB"), "5555555551234567", "PIN block must be 8 bytes long"),
        (bytes.fromhex("0F1261AAAAEDCBA9"), "5555555551234567", "PIN length must be between 4 and 12: `15`"),
        (bytes.fromhex("021261AAAAEDCBA9"), "5555555551234567", "PIN length must be between 4 and 12: `2`"),
        (bytes.fromhex("041261AAAAEDCBAA"), "5555555551234567", "PIN block filler is incorrect: `FFFFFFFFFC`"),
        (bytes.fromhex("051261AAAAEDCBA9"), "5555555551234567", "PIN is not numeric: `1234F`"),
        (bytes.fromhex("051261AAAAEDCBA9"), "555555555123", "PAN must be at least 13 digits long"),
        (bytes.fromhex("051261AAAAEDCBA9"), "5555555551234A", "PAN must be at least 13 digits long"),
    ],
)
# fmt: on
def test_decode_pinblock_iso_0_exception(
    pin_block: bytes, pan: str, error: str
) -> None:
    with pytest.raises(
        ValueError,
        match=error,
    ):
        pinblock.decode_pinblock_iso_0(pin_block, pan)


@pytest.mark.parametrize(
    ["pin", "pin_block", "pan"],
    [
        ("1234", bytes.fromhex("041261AAAAEDCBA9"), "5555555551234567"),
        ("123456789", bytes.fromhex("091261032D8DCBA9"), "5555555551234567"),
        ("1234567890", bytes.fromhex("0A1261032D82CBA9"), "5555555551234567"),
        ("123456789012", bytes.fromhex("0C1261032D8226A9"), "5555555551234567"),
    ],
)
def test_decode_pinblock_iso_0(pin: str, pin_block: bytes, pan: str) -> None:
    assert pin == pinblock.decode_pinblock_iso_0(pin_block, pan)


# fmt: off
@pytest.mark.parametrize(
    ["pin_block", "error"],
    [
        (bytes.fromhex("041234FFFFFFFFFF"), "PIN block is not ISO format 2: control field `0`"),
        (bytes.fromhex("29123456789FFF"), "PIN block must be 8 bytes long"),
        (bytes.fromhex("2F123456789012FF"), "PIN length must be between 4 and 12: `15`"),
        (bytes.fromhex("22123456789012FF"), "PIN length must be between 4 and 12: `2`"),
        (bytes.fromhex("2C123456789012CF"), "PIN block filler is incorrect: `CF`"),
        (bytes.fromhex("2C12345678901FFF"), "PIN is not numeric: `12345678901F`"),
    ],
)
# fmt: on
def test_decode_pinblock_iso_2_exception(pin_block: bytes, error: str) -> None:
    with pytest.raises(
        ValueError,
        match=error,
    ):
        pinblock.decode_pinblock_iso_2(pin_block)


@pytest.mark.parametrize(
    ["pin", "pin_block"],
    [
        ("1234", bytes.fromhex("241234FFFFFFFFFF")),
        ("123456789", bytes.fromhex("29123456789FFFFF")),
        ("1234567890", bytes.fromhex("2A1234567890FFFF")),
        ("123456789012", bytes.fromhex("2C123456789012FF")),
    ],
)
def test_decode_pinblock_iso_2(pin: str, pin_block: bytes) -> None:
    assert pin == pinblock.decode_pinblock_iso_2(pin_block)


# fmt: off
@pytest.mark.parametrize(
    ["pin_block", "pan", "error"],
    [
        (bytes.fromhex("241261AAAAEDCBA9"), "5555555551234567", "PIN block is not ISO format 3: control field `2`"),
        (bytes.fromhex("341261AAAAEDCB"), "5555555551234567", "PIN block must be 8 bytes long"),
        (bytes.fromhex("3F1261AAAAEDCBA9"), "5555555551234567", "PIN length must be between 4 and 12: `15`"),
        (bytes.fromhex("321261AAAAEDCBA9"), "5555555551234567", "PIN length must be between 4 and 12: `2`"),
        (bytes.fromhex("341261AAAAEDCBA2"), "5555555551234567", "PIN block filler is incorrect: `FFFFFFFFF4`"),
        (bytes.fromhex("351261AAAAEDCBA9"), "5555555551234567", "PIN is not numeric: `1234F`"),
        (bytes.fromhex("351261AAAAEDCBA9"), "555555555123", "PAN must be at least 13 digits long"),
        (bytes.fromhex("351261AAAAEDCBA9"), "5555555551234A", "PAN must be at least 13 digits long"),
    ],
)
# fmt: on
def test_decode_pinblock_iso_3_exception(
    pin_block: bytes, pan: str, error: str
) -> None:
    with pytest.raises(
        ValueError,
        match=error,
    ):
        pinblock.decode_pinblock_iso_3(pin_block, pan)


@pytest.mark.parametrize(
    ["pin", "pin_block", "pan"],
    [
        ("1234", bytes.fromhex("341261AAAAEDCBA9"), "5555555551234567"),
        ("123456789", bytes.fromhex("391261032D8DCBA9"), "5555555551234567"),
        ("1234567890", bytes.fromhex("3A1261032D82CBA9"), "5555555551234567"),
        ("123456789012", bytes.fromhex("3C1261032D8226A9"), "5555555551234567"),
    ],
)
def test_decode_pinblock_iso_3(pin: str, pin_block: bytes, pan: str) -> None:
    assert pin == pinblock.decode_pinblock_iso_3(pin_block, pan)


# fmt: off
@pytest.mark.parametrize(
    ["pin_block", "error"],
    [
        (bytes.fromhex("441234AAAAAAAAAA548ED7FD6549595000"), "PIN field must be 16 bytes long"),
        (bytes.fromhex("341261AAAAEDCB"), "PIN field must be 16 bytes long"),
        (bytes.fromhex("541234AAAAAAAAAA548ED7FD65495950"), "PIN block is not ISO format 4: control field `5`"),
        (bytes.fromhex("43123AAAAAAAAAAA548ED7FD65495950"), "PIN length must be between 4 and 12: `3`"),
        (bytes.fromhex("441234ABCDEFABCD548ED7FD65495950"), "PIN block filler is incorrect: `ABCDEFABCD`"),
        (bytes.fromhex("4412D4AAAAAAAAAA548ED7FD65495950"), "PIN is not numeric: `12D4`"),
    ],
)
# fmt: on
def test_decode_pinblock_iso_4_exception(pin_block: bytes, error: str) -> None:
    with pytest.raises(
        ValueError,
        match=error,
    ):
        pinblock.decode_pin_field_iso_4(pin_block)


@pytest.mark.parametrize(
    ["pin_field", "pin"],
    [
        (bytes.fromhex("441234AAAAAAAAAA548ED7FD65495950"), "1234"),
    ],
)
def test_decode_pin_field_iso_4(pin_field: bytes, pin) -> None:
    assert pin == pinblock.decode_pin_field_iso_4(pin_field)


@pytest.mark.parametrize(
    ["key", "pin_block", "pan", "error"],
    [
        (
            bytes.fromhex("C1D0F8FB4958670DBA40AB1F3752EF0D"),
            bytes.fromhex("CC17F65586BFD0953010226C4FC5B3CA00"),
            "432198765432109870",
            "Data length (17) must be multiple of AES block size 16.",
        ),
        (
            bytes.fromhex("C1D0F8FB4958670DBA40AB1F3752EF0D"),
            bytes.fromhex("CC17F65586BFD0953010226C4FC5B3CA"),
            "43219876543210987099",
            "PAN must be between 1 and 19 digits long.",
        ),
        (
            bytes.fromhex("E60B15B90ABDF14CEE337C97440F0D6E"),
            bytes.fromhex("7D5AF4C33667A2098626027FB7A9A1B7"),
            "4266229809609384667",
            "PIN block is not ISO format 4: control field `3`",
        ),
        (
            bytes.fromhex("C7BBEBA16C5AD97D5866450718C03750"),
            bytes.fromhex("2F9C910447F17293EC95DEDE1E3CA201"),
            "8220499325458689523",
            "PIN is not numeric: `1AB2`",
        ),
        (
            bytes.fromhex("820F6C7C12355BDFF1AB6CE12E8EED89"),
            bytes.fromhex("CCF310A8300B46C925A86B1098089301"),
            "939589847393485609",
            "PIN block filler is incorrect: `BBBBBBBBBB`",
        ),
        (
            bytes.fromhex("4FE3F0311936FBCE44F17159F1659CF09B2BF8913BB514A1"),
            bytes.fromhex("51334B00A6CBA3EC7B1C6F871F060AFC"),
            "2129100799029059903",
            "PIN length must be between 4 and 12: `3`",
        ),
    ],
)
# fmt: on
def test_decipher_pinblock_iso_4_exception(
    key: bytes, pin_block: bytes, pan: str, error: str
) -> None:
    with pytest.raises(ValueError) as e:
        pinblock.decipher_pinblock_iso_4(key, pin_block, pan)
    assert e.value.args[0] == error


@pytest.mark.parametrize(
    ["key", "pin_block", "pan", "pin"],
    [
        # Test vector from ep2 - eft/pos 2000 Security Specification, Version 8.0.0, 8.4: PIN Encryption
        (
            bytes.fromhex("C1D0F8FB4958670DBA40AB1F3752EF0D"),
            bytes.fromhex("CC17F65586BFD0953010226C4FC5B3CA"),
            "432198765432109870",
            "1234",
        ),
        # PAN length < 12
        (
            bytes.fromhex("00112233445566778899AABBCCDDEEFF"),
            bytes.fromhex("39B69B1B91FE05D48F7EF0D68EB2CBD6"),
            "1",
            "123456",
        ),
    ],
)
def test_decipher_pinblock_iso_4(
    key: bytes, pin_block: bytes, pan: str, pin: str
) -> None:
    assert pin == pinblock.decipher_pinblock_iso_4(key, pin_block, pan)
