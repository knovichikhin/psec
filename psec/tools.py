import sys as _sys

__all__ = [
    "xor",
    "odd_parity",
]


def xor(data: bytes, key: bytes) -> bytes:
    r"""Apply "exlusive or" to two bytes instances.
    Many thanks:
    https://stackoverflow.com/a/29409299

    Parameters
    ----------
    data : bytes
        Data to be XOR'd
    key : bytes
        Bit mask used to XOR data

    Returns
    -------
    bytes
        Data XOR'd by key
    """
    key = key[: len(data)]
    int_var = int.from_bytes(data, _sys.byteorder)
    int_key = int.from_bytes(key, _sys.byteorder)
    int_enc = int_var ^ int_key
    return int_enc.to_bytes(len(data), _sys.byteorder)


def odd_parity(v: int) -> int:
    r"""Check integer parity.
    Many thanks: in_parallel
    http://p-nand-q.com/python/_algorithms/math/bit-parity.html

    Parameters
    ----------
    v : int
        Integer to check parity of

    Returns
    -------
    int
        0 = even parity (even number of bits enabled, e.g. 0, 3, 5)
        1 = odd parity (odd number of bits enabled, e.g. 1, 2, 4)
    """
    v ^= v >> 16
    v ^= v >> 8
    v ^= v >> 4
    v &= 0xF
    return (0x6996 >> v) & 1
