from typing import Union
import pytest
from psec import pinblock


def test_encode_pin_block_iso_2_exception() -> None:
    with pytest.raises(
        ValueError,
        match="PIN must be between 4 and 12 digits long",
    ):
        pinblock.encode_pin_block_iso_2("1")


@pytest.mark.parametrize(
    ["pin", "pin_block"],
    [
        ("1234", "241234FFFFFFFFFF"),
        ("123456789", "29123456789FFFFF"),
        ("1234567890", "2A1234567890FFFF"),
        ("123456789012", "2C123456789012FF"),
        (b"1234", "241234FFFFFFFFFF"),
        (b"123456789", "29123456789FFFFF"),
        (b"1234567890", "2A1234567890FFFF"),
        (b"123456789012", "2C123456789012FF"),
    ],
)
def test_encode_pin_block_iso_2(pin: Union[bytes, str], pin_block: str) -> None:
    assert pin_block == pinblock.encode_pin_block_iso_2(pin).hex().upper()


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
def test_decode_pin_block_iso_2_exception(pin_block: bytes, error: str) -> None:
    with pytest.raises(
        ValueError,
        match=error,
    ):
        pinblock.decode_pin_block_iso_2(pin_block)


@pytest.mark.parametrize(
    ["pin", "pin_block"],
    [
        ("1234", bytes.fromhex("241234FFFFFFFFFF")),
        ("123456789", bytes.fromhex("29123456789FFFFF")),
        ("1234567890", bytes.fromhex("2A1234567890FFFF")),
        ("123456789012", bytes.fromhex("2C123456789012FF")),
    ],
)
def test_decode_pin_block_iso_2(pin: str, pin_block: bytes) -> None:
    assert pin == pinblock.decode_pin_block_iso_2(pin_block)
