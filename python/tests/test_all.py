import pytest
import easy_pow


def test_create_plaintext_matrix():
    assert easy_pow.crate_plaintext_matrix(length=10, prefix=b"abc", suffix=b"efg") == [
        b"a",
        b"b",
        b"c",
        b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
        b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
        b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
        b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
        b"e",
        b"f",
        b"g",
    ]


@pytest.mark.parametrize(
    ("length", "prefix", "suffix", "charset", "expected_exception", "expected_match"),
    [
        ("20", b"aaaaaa", b"aaaaa", b"12345", TypeError, r"length must be int"),
        (20, b"aaaaaa", b"aaaaa", "12345", TypeError, r"charset must be bytes"),
        (20, "aaaaaa", b"aaaaa", b"12345", TypeError, r"prefix must be bytes"),
        (20, b"aaaaaa", "aaaaa", b"12345", TypeError, r"suffix must be bytes"),
        (10, b"aaaaaa", b"aaaaa", b"12345", ValueError, r"length must.+"),
    ],
)
def test_create_plaintext_matrix_error(
    length, prefix, suffix, charset, expected_exception, expected_match
):
    with pytest.raises(expected_exception, match=expected_match):
        easy_pow.crate_plaintext_matrix(
            length, prefix=prefix, suffix=suffix, charset=charset
        )
