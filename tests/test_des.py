import pytest
import psec


# fmt: off
@pytest.mark.parametrize(
    ["key", "variant", "error"],
    [
        (b"AAAAAAA", 1, "Key must be a single, double or triple DES key"),
        (b"AAAAAAAABBBBBBBBCCCCCCCC", -1, "Variant must be in the range of 0 to 31"),
        (b"AAAAAAAABBBBBBBB", -1, "Variant must be in the range of 0 to 31"),
        (b"AAAAAAAA", 32, "Variant must be in the range of 0 to 31"),
    ],
)
# fmt: on
def test_key_variant_exceptions(key: bytes, variant: int, error: str) -> None:
    with pytest.raises(ValueError, match=error):
        psec.des.apply_key_variant(key, variant)


# fmt: off
@pytest.mark.parametrize(
    ["key", "variant", "key_variant"],
    [
        ("0000000000000000", 1, "0800000000000000"),
        ("0000000000000000", 31, "F800000000000000"),
        ("00000000000000010000000000000002", 1, "08000000000000010800000000000002"),
        ("00000000000000010000000000000002", 31, "F800000000000001F800000000000002"),
        ("000000000000000100000000000000020000000000000003", 1, "080000000000000108000000000000020800000000000003"),
        ("000000000000000100000000000000020000000000000003", 31, "F800000000000001F800000000000002F800000000000003"),
    ],
)
# fmt: on
def test_key_variant(key: str, variant: int, key_variant: str) -> None:
    result = psec.des.apply_key_variant(bytes.fromhex(key), variant)
    assert result.hex().upper() == key_variant


def test_encrypt_des_cbc_exception() -> None:
    with pytest.raises(ValueError) as e:
        psec.des.encrypt_tdes_cbc(b"1" * 16, b"0" * 16, b"")
    assert e.value.args[0] == "Data length (0) must be multiple of DES block size 8."

    with pytest.raises(ValueError) as e:
        psec.des.encrypt_tdes_cbc(b"1" * 16, b"0" * 16, b"2" * 17)
    assert e.value.args[0] == "Data length (17) must be multiple of DES block size 8."


def test_decrypt_des_cbc_exception() -> None:
    with pytest.raises(ValueError) as e:
        psec.des.decrypt_tdes_cbc(b"1" * 16, b"0" * 16, b"")
    assert e.value.args[0] == "Data length (0) must be multiple of DES block size 8."

    with pytest.raises(ValueError) as e:
        psec.des.decrypt_tdes_cbc(b"1" * 16, b"0" * 16, b"2" * 17)
    assert e.value.args[0] == "Data length (17) must be multiple of DES block size 8."


def test_encrypt_des_ecb_exception() -> None:
    with pytest.raises(ValueError) as e:
        psec.des.encrypt_tdes_ecb(b"1" * 16, b"")
    assert e.value.args[0] == "Data length (0) must be multiple of DES block size 8."

    with pytest.raises(ValueError) as e:
        psec.des.encrypt_tdes_ecb(b"1" * 16, b"2" * 17)
    assert e.value.args[0] == "Data length (17) must be multiple of DES block size 8."


def test_decrypt_des_ecb_exception() -> None:
    with pytest.raises(ValueError) as e:
        psec.des.decrypt_tdes_ecb(b"1" * 16, b"")
    assert e.value.args[0] == "Data length (0) must be multiple of DES block size 8."

    with pytest.raises(ValueError) as e:
        psec.des.decrypt_tdes_ecb(b"1" * 16, b"2" * 17)
    assert e.value.args[0] == "Data length (17) must be multiple of DES block size 8."
