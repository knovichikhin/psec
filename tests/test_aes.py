import pytest
from psec import aes


def test_encrypt_aes_cbc_exception() -> None:
    with pytest.raises(ValueError) as e:
        aes.encrypt_aes_cbc(b"1" * 16, b"0" * 16, b"")
    assert e.value.args[0] == "Data length (0) must be multiple of AES block size 16."

    with pytest.raises(ValueError) as e:
        aes.encrypt_aes_cbc(b"1" * 16, b"0" * 16, b"2" * 17)
    assert e.value.args[0] == "Data length (17) must be multiple of AES block size 16."


def test_decrypt_aes_cbc_exception() -> None:
    with pytest.raises(ValueError) as e:
        aes.decrypt_aes_cbc(b"1" * 16, b"0" * 16, b"")
    assert e.value.args[0] == "Data length (0) must be multiple of AES block size 16."

    with pytest.raises(ValueError) as e:
        aes.decrypt_aes_cbc(b"1" * 16, b"0" * 16, b"2" * 17)
    assert e.value.args[0] == "Data length (17) must be multiple of AES block size 16."


def test_encrypt_aes_ecb_exception() -> None:
    with pytest.raises(ValueError) as e:
        aes.encrypt_aes_ecb(b"1" * 16, b"")
    assert e.value.args[0] == "Data length (0) must be multiple of AES block size 16."

    with pytest.raises(ValueError) as e:
        aes.encrypt_aes_ecb(b"1" * 16, b"2" * 17)
    assert e.value.args[0] == "Data length (17) must be multiple of AES block size 16."


def test_decrypt_aes_ecb_exception() -> None:
    with pytest.raises(ValueError) as e:
        aes.decrypt_aes_ecb(b"1" * 16, b"")
    assert e.value.args[0] == "Data length (0) must be multiple of AES block size 16."

    with pytest.raises(ValueError) as e:
        aes.decrypt_aes_ecb(b"1" * 16, b"2" * 17)
    assert e.value.args[0] == "Data length (17) must be multiple of AES block size 16."
