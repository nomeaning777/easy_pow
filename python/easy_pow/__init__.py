from typing import List, Tuple
from .easy_pow import *


def target_suffix(suffix: bytes, length: int) -> Tuple[bytes, bytes]:
    if type(suffix) is not bytes:
        raise TypeError("suffix must be bytes")
    if type(length) is not int:
        raise TypeError("length must be int")
    if len(suffix) > length:
        raise ValueError("length must be greater than or equal to the length of suffix")

    target_hash = b"\0" * (length - len(suffix)) + suffix
    target_hash_mask = b"\0" * (length - len(suffix)) + b"\xff" * len(suffix)
    return (target_hash, target_hash_mask)


def target_prefix(prefix: bytes, length: int) -> Tuple[bytes, bytes]:
    if type(prefix) is not bytes:
        raise TypeError("prefix must be bytes")
    if type(length) is not int:
        raise TypeError("length must be int")
    if len(prefix) > length:
        raise ValueError("length must be greater than or equal to the length of prefix")

    target_hash = prefix + b"\0" * (length - len(prefix))
    target_hash_mask = b"\xff" * len(prefix) + b"\0" * (length - len(prefix))
    return (target_hash, target_hash_mask)


def crate_plaintext_matrix(
    length: int,
    prefix: bytes = b"",
    suffix: bytes = b"",
    charset: bytes = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
) -> List[bytearray]:
    if type(prefix) is not bytes:
        raise TypeError("prefix must be bytes")
    if type(suffix) is not bytes:
        raise TypeError("suffix must be bytes")
    if type(charset) is not bytes:
        raise TypeError("charset must be bytes")
    if type(length) is not int:
        raise TypeError("length must be int")
    if len(prefix) + len(suffix) > length:
        raise ValueError(
            "length must be greater than or equal to the sum of the lengths of prefix and suffix"
        )
    return (
        [prefix[i : i + 1] for i in range(len(prefix))]
        + [charset] * (length - len(prefix) - len(suffix))
        + [suffix[i : i + 1] for i in range(len(suffix))]
    )


__doc__ = easy_pow.__doc__
if hasattr(easy_pow, "__all__"):
    __all__ = easy_pow.__all__
