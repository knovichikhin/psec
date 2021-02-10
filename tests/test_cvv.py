import pytest
from psec import cvv


# fmt: off
@pytest.mark.parametrize(
    ["cvk", "pan", "expiry", "sc", "error"],
    [
        (b"AAAAAAAA", "5555555551234567", "2012", "220", "CVK must be a double length DES key"),
        (b"AAAAAAAABBBBBBBBCCCCCCCC", "5555555551234567", "2012", "220", "CVK must be a double length DES key"),
        (b"AAAAAAAABBBBBBBB", "55555555512345671234", "2012", "220", "PAN must be less than 19 digits"),
        (b"AAAAAAAABBBBBBBB", "555555555123456A", "2012", "220", "PAN must be less than 19 digits"),
        (b"AAAAAAAABBBBBBBB", "5555555551234567", "201", "220", "PAN expiry must be 4 digits long"),
        (b"AAAAAAAABBBBBBBB", "5555555551234567", "20120", "220", "PAN expiry must be 4 digits long"),
        (b"AAAAAAAABBBBBBBB", "5555555551234567", "201A", "220", "PAN expiry must be 4 digits long"),
        (b"AAAAAAAABBBBBBBB", "5555555551234567", "2012", "2202", "Service code must be 3 digits long"),
        (b"AAAAAAAABBBBBBBB", "5555555551234567", "2012", "22", "Service code must be 3 digits long"),
        (b"AAAAAAAABBBBBBBB", "5555555551234567", "2012", "22A", "Service code must be 3 digits long"),
    ],
)
# fmt: on
def test_generate_cvv_exceptions(
    cvk: bytes, pan: str, expiry: str, sc: str, error: str
) -> None:
    with pytest.raises(ValueError, match=error):
        cvv.generate_cvv(cvk, pan, expiry, sc)


def test_generate_cvv() -> None:
    cvk = "99999999999999998888888888888888"
    card_cvv = cvv.generate_cvv(bytes.fromhex(cvk), "2222222222222222", "3333", "111")
    assert card_cvv == "361"
