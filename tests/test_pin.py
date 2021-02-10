import pytest
import psec


# fmt: off
@pytest.mark.parametrize(
    ["pvk", "conversion_table", "offset", "pan", "pan_verify_offset", "pan_verify_length", "pan_pad", "error"],
    [
        (b"1234", "1234567890123456", "0000", "1122334455667788", 0, 16, "F", "PVK must be a DES key"),
        (b"12345678", "123456789012345", "0000", "1122334455667788", 0, 16, "F", "Conversion table must 16 digits"),
        (b"12345678", "12345678901234567", "0000", "1122334455667788", 0, 16, "F", "Conversion table must 16 digits"),
        (b"12345678", "123456789012345A", "0000", "1122334455667788", 0, 16, "F", "Conversion table must 16 digits"),
        (b"12345678", "1234567890123456", "000", "1122334455667788", 0, 16, "F", "Offset must be from 4 to 16 digits"),
        (b"12345678", "1234567890123456", "00000000000000000", "1122334455667788", 0, 16, "F", "Offset must be from 4 to 16 digits"),
        (b"12345678", "1234567890123456", "000A", "1122334455667788", 0, 16, "F", "Offset must be from 4 to 16 digits"),
        (b"12345678", "1234567890123456", "0000", "11223344556677889900", 0, 16, "F", "PAN must be less than 19 digits"),
        (b"12345678", "1234567890123456", "0000", "112233445566778A", 0, 16, "F", "PAN must be less than 19 digits"),
        (b"12345678", "1234567890123456", "0000", "1122334455667788", 0, 16, "", "PAN pad character must be valid hex digit"),
        (b"12345678", "1234567890123456", "0000", "1122334455667788", 0, 16, "FF", "PAN pad character must be valid hex digit"),
        (b"12345678", "1234567890123456", "0000", "1122334455667788", 0, 16, "X", "PAN pad character must be valid hex digit"),
        (b"12345678", "1234567890123456", "0000", "1122334455667788", 1, 16, "F", "PAN verify offset and length must be within provided PAN"),
        (b"12345678", "1234567890123456", "0000", "1122334455667788", 0, 17, "F", "PAN verify offset and length must be within provided PAN"),
    ],
)
# fmt: on
def test_generate_ibm3624_pin_exceptions(
    pvk: bytes,
    conversion_table: str,
    offset: str,
    pan: str,
    pan_verify_offset: int,
    pan_verify_length: int,
    pan_pad: str,
    error: str,
) -> None:
    with pytest.raises(ValueError, match=error):
        psec.pin.generate_ibm3624_pin(
            pvk,
            conversion_table,
            offset,
            pan,
            pan_verify_offset,
            pan_verify_length,
            pan_pad,
        )


# fmt: off
@pytest.mark.parametrize(
    ["conversion_table", "offset", "pan", "pan_verify_offset", "pan_verify_length", "pan_pad", "result_pin"],
    [
        ("1234567890123456", "0000", "1122334455667788", 0, 16, "F", "4524"),
        ("1234567890123456", "0000", "1122334455667788", 0, 16, "f", "4524"),
        ("1234567890123456", "1111", "1122334455667788", 0, 16, "F", "5635"),
        ("1234567890123456", "6586", "1122334455667788", 0, 16, "F", "0000"),
        ("1234567890123456", "7697", "1122334455667788", 0, 16, "F", "1111"),
        ("1234567890123456", "7710", "1122334455667788", 0, 16, "F", "1234"),
        ("1234567890123456", "0000", "1122334455667788", 0, 14, "F", "5518"),
        ("1234567890123456", "0000", "1122334455667788", 0, 14, "f", "5518"),
        ("1234567890123456", "0000", "1122334455667788", 1, 14, "1", "3675"),
        ("1234567890123456", "0000", "1122334455667788", 2, 14, "1", "5550"),
    ],
)
# fmt: on
def test_generate_ibm3624_pin(
    conversion_table: str,
    offset: str,
    pan: str,
    pan_verify_offset: int,
    pan_verify_length: int,
    pan_pad: str,
    result_pin: str,
) -> None:
    pvk = bytes.fromhex("0123456789ABCDEFFEDCBA9876543210")
    pin = psec.pin.generate_ibm3624_pin(
        pvk,
        conversion_table,
        offset,
        pan,
        pan_verify_offset,
        pan_verify_length,
        pan_pad,
    )
    assert result_pin == pin


# fmt: off
@pytest.mark.parametrize(
    ["pvk", "conversion_table", "pin", "pan", "pan_verify_offset", "pan_verify_length", "pan_pad", "error"],
    [
        (b"1234", "1234567890123456", "0000", "1122334455667788", 0, 16, "F", "PVK must be a DES key"),
        (b"12345678", "123456789012345", "0000", "1122334455667788", 0, 16, "F", "Conversion table must 16 digits"),
        (b"12345678", "12345678901234567", "0000", "1122334455667788", 0, 16, "F", "Conversion table must 16 digits"),
        (b"12345678", "123456789012345A", "0000", "1122334455667788", 0, 16, "F", "Conversion table must 16 digits"),
        (b"12345678", "1234567890123456", "000", "1122334455667788", 0, 16, "F", "PIN must be from 4 to 16 digits"),
        (b"12345678", "1234567890123456", "00000000000000000", "1122334455667788", 0, 16, "F", "PIN must be from 4 to 16 digits"),
        (b"12345678", "1234567890123456", "000A", "1122334455667788", 0, 16, "F", "PIN must be from 4 to 16 digits"),
        (b"12345678", "1234567890123456", "0000", "11223344556677889900", 0, 16, "F", "PAN must be less than 19 digits"),
        (b"12345678", "1234567890123456", "0000", "112233445566778A", 0, 16, "F", "PAN must be less than 19 digits"),
        (b"12345678", "1234567890123456", "0000", "1122334455667788", 0, 16, "", "PAN pad character must be valid hex digit"),
        (b"12345678", "1234567890123456", "0000", "1122334455667788", 0, 16, "FF", "PAN pad character must be valid hex digit"),
        (b"12345678", "1234567890123456", "0000", "1122334455667788", 0, 16, "X", "PAN pad character must be valid hex digit"),
        (b"12345678", "1234567890123456", "0000", "1122334455667788", 1, 16, "F", "PAN verify offset and length must be within provided PAN"),
        (b"12345678", "1234567890123456", "0000", "1122334455667788", 0, 17, "F", "PAN verify offset and length must be within provided PAN"),
    ],
)
# fmt: on
def test_generate_ibm3624_offset_exceptions(
    pvk: bytes,
    conversion_table: str,
    pin: str,
    pan: str,
    pan_verify_offset: int,
    pan_verify_length: int,
    pan_pad: str,
    error: str,
) -> None:
    with pytest.raises(ValueError, match=error):
        psec.pin.generate_ibm3624_offset(
            pvk,
            conversion_table,
            pin,
            pan,
            pan_verify_offset,
            pan_verify_length,
            pan_pad,
        )


# fmt: off
@pytest.mark.parametrize(
    ["conversion_table", "pin", "pan", "pan_verify_offset", "pan_verify_length", "pan_pad", "result_offset"],
    [
        ("1234567890123456", "4524", "1122334455667788", 0, 16, "F", "0000"),
        ("1234567890123456", "4524", "1122334455667788", 0, 16, "f", "0000"),
        ("1234567890123456", "5635", "1122334455667788", 0, 16, "F", "1111"),
        ("1234567890123456", "0000", "1122334455667788", 0, 16, "F", "6586"),
        ("1234567890123456", "1111", "1122334455667788", 0, 16, "F", "7697"),
        ("1234567890123456", "1234", "1122334455667788", 0, 16, "F", "7710"),
        ("1234567890123456", "5518", "1122334455667788", 0, 14, "F", "0000"),
        ("1234567890123456", "5518", "1122334455667788", 0, 14, "f", "0000"),
        ("1234567890123456", "3675", "1122334455667788", 1, 14, "1", "0000"),
        ("1234567890123456", "5550", "1122334455667788", 2, 14, "1", "0000"),
    ],
)
# fmt: on
def test_generate_ibm3624_offset(
    conversion_table: str,
    pin: str,
    pan: str,
    pan_verify_offset: int,
    pan_verify_length: int,
    pan_pad: str,
    result_offset: str,
) -> None:
    pvk = bytes.fromhex("0123456789ABCDEFFEDCBA9876543210")
    offset = psec.pin.generate_ibm3624_offset(
        pvk,
        conversion_table,
        pin,
        pan,
        pan_verify_offset,
        pan_verify_length,
        pan_pad,
    )
    assert result_offset == offset


# fmt: off
@pytest.mark.parametrize(
    ["pvk", "pvki", "pin", "pan", "error"],
    [
        (b"1234", "1", "0000", "1122334455667788", "PVK must be a DES key"),
        (b"", "1", "0000", "1122334455667788", "PVK must be a DES key"),
        (b"12345678", "A", "0000", "1122334455667788", 'PVKI must be 1 digit from "0" to "9"'),
        (b"12345678", "11", "0000", "1122334455667788", 'PVKI must be 1 digit from "0" to "9"'),
        (b"12345678", "", "0000", "1122334455667788", 'PVKI must be 1 digit from "0" to "9"'),
        (b"12345678", "1", "000", "1122334455667788", "PIN must be 4 digits"),
        (b"12345678", "1", "00000", "1122334455667788", "PIN must be 4 digits"),
        (b"12345678", "1", "A000", "1122334455667788", "PIN must be 4 digits"),
        (b"12345678", "1", "000D", "1122334455667788", "PIN must be 4 digits"),
        (b"12345678", "1", "", "1122334455667788", "PIN must be 4 digits"),
        (b"12345678", "1", "0000", "11223344556", "PAN must be more than 12 digits"),
        (b"12345678", "1", "0000", "1122334455A", "PAN must be more than 12 digits"),
        (b"12345678", "1", "0000", "", "PAN must be more than 12 digits"),
    ],
)
# fmt: on
def test_generate_visa_pvv_exceptions(
    pvk: bytes,
    pvki: str,
    pin: str,
    pan: str,
    error: str,
) -> None:
    with pytest.raises(ValueError, match=error):
        psec.pin.generate_visa_pvv(pvk, pvki, pin, pan)


# fmt: off
@pytest.mark.parametrize(
    ["pvki", "pin", "pan", "result_pvv"],
    [
        ("1", "4524", "1122334455667788", "8523"),
        ("2", "1912", "1122334455667788", "3244"),
        ("1", "0570", "1122334455667718", "3144"),
        ("1", "8299", "1122334455667708", "4422"),
    ],
)
# fmt: on
def test_generate_visa_pvv(
    pvki: str,
    pin: str,
    pan: str,
    result_pvv: str,
) -> None:
    pvk = bytes.fromhex("0123456789ABCDEFFEDCBA9876543210")
    assert result_pvv == psec.pin.generate_visa_pvv(
        pvk,
        pvki,
        pin,
        pan,
    )
