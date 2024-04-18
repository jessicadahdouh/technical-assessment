from helpers.custom_exceptions import PasswordFormatError
from unittest.mock import patch
from helpers.utils import (
    validate_password,
    generate_access_token,
    decode_access_token,
    connect_to_mongo,
    hash_password,
    verify_password
)
import pytest


@pytest.mark.parametrize("password, expected_result", [
    ("ValidPassword123!", True),  # Valid password
    ("invalid", PasswordFormatError),  # Too short
    ("no_numbers", PasswordFormatError),  # No numbers
    ("NO_LOWER", PasswordFormatError),  # No lowercase letters
    ("no_upper123", PasswordFormatError),  # No uppercase letters
    ("no_symbol123", PasswordFormatError),  # No symbols
])
def test_validate_password(password, expected_result):
    if expected_result is True:
        assert validate_password(password) == expected_result
    else:
        with pytest.raises(expected_result):
            validate_password(password)


def test_hash_password():
    password = "TestPassword123!"
    hashed_password = hash_password(password)
    assert hashed_password != password  # Ensure password is hashed


def test_verify_password():
    password = "TestPassword123!"
    hashed_password = hash_password(password)
    assert verify_password(password, hashed_password)  # Verify correct password


def test_generate_access_token():
    payload = {"username": "test"}
    token = generate_access_token(payload)
    assert isinstance(token, str)  # Ensure token is generated


def test_decode_access_token():
    payload = {"username": "test"}
    token = generate_access_token(payload)
    decoded_payload = decode_access_token(token)
    assert decoded_payload["username"] == payload["username"]  # Ensure decoded payload matches original payload


@pytest.mark.parametrize("host, port, username, password, database, auth_db, expected_result", [
    ("localhost", "27017", "user", "password", "mydatabase", "auth_db", True),  # Valid connection
    ("fake", "27017", None, None, "mydatabase", "auth_db", Exception),  # Invalid connection without authentication
])
def test_connect_to_mongo(host, port, username, password, database, auth_db, expected_result, mocker):
    mocker.patch("helpers.utils.connect")
    try:
        connect_to_mongo(host, port, username, password, database, auth_db)
        assert expected_result
    except ValueError:
        assert not expected_result
