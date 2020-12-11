from typing import Union
import pytest
from psec import cvv


def test_generate_cvv_exceptions() -> None:
    # CVK length
    with pytest.raises(
        ValueError,
        match="CVK must be a double length DES key",
    ):
        cvv.generate_cvv(b"AAAAAAAA", "12345678901214", "9912", "220")

    # PAN length
    with pytest.raises(
        ValueError,
        match="PAN must be less than 19 digits",
    ):
        cvv.generate_cvv(b"AAAAAAAABBBBBBBB", "12345678901214567890", "9912", "220")

    # PAN length
    with pytest.raises(
        ValueError,
        match="PAN expiry must be 4 digits long",
    ):
        cvv.generate_cvv(b"AAAAAAAABBBBBBBB", "12345678901214", "99121", "220")

    # Service code length
    with pytest.raises(
        ValueError,
        match="Service code must be 3 digits long",
    ):
        cvv.generate_cvv(b"AAAAAAAABBBBBBBB", "12345678901214", "9912", "2201")


@pytest.mark.parametrize(
    ["pan", "expiry", "svc"],
    [
        (b"2222222222222222", "3333", "111"),
        ("2222222222222222", b"3333", "111"),
        ("2222222222222222", "3333", b"111"),
    ],
)
def test_generate_cvv(
    pan: Union[bytes, str], expiry: Union[bytes, str], svc: Union[bytes, str]
) -> None:
    cvk = "99999999999999998888888888888888"
    card_cvv = cvv.generate_cvv(bytes.fromhex(cvk), pan, expiry, svc)
    assert card_cvv == "361"
