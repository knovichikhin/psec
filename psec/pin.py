from psec import des as _des
from psec import tools as _tools

__all__ = [
    "generate_ibm3624_pin",
    "generate_ibm3624_offset",
    "generate_visa_pvv",
]


def generate_ibm3624_pin(
    pvk: bytes,
    conversion_table: str,
    offset: str,
    pan: str,
    pan_verify_offset: int,
    pan_verify_length: int,
    pan_pad: str,
) -> str:
    r"""Generate IBM 3624 PIN based on PAN.

    Parameters
    ----------
    pvk : bytes
        Binary PIN verification key. Has to be a valid Triple DES key.
    conversion_table : str
        Conversion table to map hexadecimal digits to decimal digits.
        This field contains 16 decimal digits.
    offset : str
        Offset applied to the generated (natural) PIN.
        Has to be 4-16 digits. Length of offset determines PIN length.
        Provide offset of all zeros to generate natural PIN.
    pan : str
        Primary Account Number to serve as validation data
    pan_verify_offset : int
        Offset in PAN to start validation data
    pan_verify_length : int
        Lenght of PAN to include into validation data
    pan_pad : str
        Character to pad validation data if not 16 characters long.
        Has to be a valid hex character.

    Returns
    -------
    pin : str
        Cardholder Personal Identification Number

    Raises
    ------
    ValueError
        PVK must be a DES key
        Conversion table must 16 digits
        Offset must be from 4 to 16 digits
        PAN must be less than 19 digit
        PAN pad character must be valid hex digit
        PAN verify offset and length must be within provided PAN

    Examples
    --------
    >>> import psec
    >>> pvk = bytes.fromhex("0123456789ABCDEFFEDCBA9876543210")
    >>> psec.pin.generate_ibm3624_pin(
    ...     pvk,
    ...     conversion_table="1234567890123456",
    ...     offset="0000",
    ...     pan="1122334455667788",
    ...     pan_verify_offset=0,
    ...     pan_verify_length=16,
    ...     pan_pad="F")
    '4524'
    """
    if len(pvk) not in {8, 16, 24}:
        raise ValueError("PVK must be a DES key")

    if len(conversion_table) != 16 or not _tools.ascii_numeric(conversion_table):
        raise ValueError("Conversion table must 16 digits")

    if len(offset) < 4 or len(offset) > 16 or not _tools.ascii_numeric(offset):
        raise ValueError("Offset must be from 4 to 16 digits")

    if len(pan) > 19 or not _tools.ascii_numeric(pan):
        raise ValueError("PAN must be less than 19 digits")

    if len(pan_pad) != 1 or not _tools.ascii_hexchar(pan_pad):
        raise ValueError("PAN pad character must be valid hex digit")

    validation_data = pan[pan_verify_offset : pan_verify_length + pan_verify_offset]

    if len(validation_data) != pan_verify_length:
        raise ValueError("PAN verify offset and length must be within provided PAN")

    validation_data = validation_data[:16].ljust(16, pan_pad[:1]).upper()

    intermediate_pin = (
        _des.encrypt_tdes_ecb(pvk, bytes.fromhex(validation_data)).hex().upper()
    )
    intermediate_pin = str.translate(
        intermediate_pin, str.maketrans("0123456789ABCDEF", conversion_table)
    )

    return "".join(
        str(int(intermediate_pin[i]) + int(offset[i]))[-1:]
        for i in range(0, len(offset))
    )


def generate_ibm3624_offset(
    pvk: bytes,
    conversion_table: str,
    pin: str,
    pan: str,
    pan_verify_offset: int,
    pan_verify_length: int,
    pan_pad: str,
) -> str:
    r"""Generate IBM 3624 PIN based on PAN.

    Parameters
    ----------
    pvk : bytes
        Binary PIN verification key. Has to be a valid Triple DES key.
    conversion_table : str
        Conversion table to map hexadecimal digits to decimal digits.
        This field contains 16 decimal digits.
    pin : str
        Cardholder Personal Identification Number
    pan : str
        Primary Account Number to serve as validation data
    pan_verify_offset : int
        Offset in PAN to start validation data
    pan_verify_length : int
        Lenght of PAN to include into validation data
    pan_pad : str
        Character to pad validation data if not 16 characters long.
        Has to be a valid hex character.

    Returns
    -------
    offset : str
        Offset applied to the generated (natural) PIN to arrive
        at cardholder PIN.

    Raises
    ------
    ValueError
        PVK must be a DES key
        Conversion table must 16 digits
        PIN must be from 4 to 16 digits
        PAN must be less than 19 digit
        PAN pad character must be valid hex digit
        PAN verify offset and length must be within provided PAN

    Examples
    --------
    >>> import psec
    >>> pvk = bytes.fromhex("0123456789ABCDEFFEDCBA9876543210")
    >>> psec.pin.generate_ibm3624_offset(
    ...     pvk,
    ...     conversion_table="1234567890123456",
    ...     pin="4524",
    ...     pan="1122334455667788",
    ...     pan_verify_offset=0,
    ...     pan_verify_length=16,
    ...     pan_pad="F")
    '0000'
    """
    if len(pvk) not in {8, 16, 24}:
        raise ValueError("PVK must be a DES key")

    if len(conversion_table) != 16 or not _tools.ascii_numeric(conversion_table):
        raise ValueError("Conversion table must 16 digits")

    if len(pin) < 4 or len(pin) > 16 or not _tools.ascii_numeric(pin):
        raise ValueError("PIN must be from 4 to 16 digits")

    if len(pan) > 19 or not _tools.ascii_numeric(pan):
        raise ValueError("PAN must be less than 19 digits")

    if len(pan_pad) != 1 or not _tools.ascii_hexchar(pan_pad):
        raise ValueError("PAN pad character must be valid hex digit")

    validation_data = pan[pan_verify_offset : pan_verify_length + pan_verify_offset]

    if len(validation_data) != pan_verify_length:
        raise ValueError("PAN verify offset and length must be within provided PAN")

    validation_data = validation_data[:16].ljust(16, pan_pad[:1]).upper()

    intermediate_pin = (
        _des.encrypt_tdes_ecb(pvk, bytes.fromhex(validation_data)).hex().upper()
    )
    intermediate_pin = str.translate(
        intermediate_pin, str.maketrans("0123456789ABCDEF", conversion_table)
    )

    return "".join(
        str(10 + int(pin[i]) - int(intermediate_pin[i]))[-1:]
        for i in range(0, len(pin))
    )


def generate_visa_pvv(
    pvk: bytes,
    pvki: str,
    pin: str,
    pan: str,
) -> str:
    r"""Generate Visa PIN Verification Value.

    Parameters
    ----------
    pvk : bytes
        Binary PIN Verification Key. Has to be a valid Triple DES key.
    pvki : str
        PIN Verification Key Index used in the algorithm to calculate.
        Contains 1 decimal digit in the range from "0" to "9".
    pin : str
        Cardholder Personal Identification Number
    pan : str
        Primary Account Number.

    Returns
    -------
    pvv : str
        4-digit PIN Verification Value.

    Raises
    ------
    ValueError
        PVK must be a DES key
        PVKI must be 1 digit from "0" to "9"
        PIN must be 4 digits
        PAN must be more than 12 digits

    Examples
    --------
    >>> import psec
    >>> pvk = bytes.fromhex("0123456789ABCDEFFEDCBA9876543210")
    >>> psec.pin.generate_visa_pvv(
    ...     pvk,
    ...     pvki="3",
    ...     pin="4524",
    ...     pan="1122334455667788")
    '4021'
    """

    if len(pvk) not in {8, 16, 24}:
        raise ValueError("PVK must be a DES key")

    if len(pvki) != 1 or not _tools.ascii_numeric(pvki):
        raise ValueError('PVKI must be 1 digit from "0" to "9"')

    if len(pin) != 4 or not _tools.ascii_numeric(pin):
        raise ValueError("PIN must be 4 digits")

    if len(pan) < 12 or not _tools.ascii_numeric(pan):
        raise ValueError("PAN must be more than 12 digits")

    # Form a "Transformed Security Parameter"
    tsp = pan[-12:-1] + pvki + pin
    tsp = _des.encrypt_tdes_ecb(pvk, bytes.fromhex(tsp)).hex()

    # 4 digits from TSP form a PVV
    pvv = "".join(
        [c for c in tsp if c in {"1", "2", "3", "4", "5", "6", "7", "8", "9", "0"}][:4]
    )

    # If there are not enough digits, substitute letters in TSP with digits:
    # Input  a b c d e f
    # Output 0 1 2 3 4 5
    if len(pvv) < 4:
        pvv2 = "".join(
            [c for c in tsp if c in {"a", "b", "c", "d", "e", "f"}][: 4 - len(pvv)]
        )
        pvv2 = pvv2.translate({97: 48, 98: 49, 99: 50, 100: 51, 101: 52, 102: 53})
        pvv = pvv + pvv2

    return pvv
