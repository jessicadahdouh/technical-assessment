from helpers.custom_exceptions import PasswordFormatError
from datetime import datetime, timedelta
from settings import jwt_secret_key
from mongoengine import connect
import bcrypt
import jwt
import re


ALGORITHM = "HS256"
# Token expiration time (in minutes)
TOKEN_EXPIRE_MINUTES = 30


def validate_password(password: str) -> bool:
    """
    Validate if the password meets the given guidelines:
    - Contains at least 1 symbol
    - Contains at least 1 capital letter
    - Contains at least 1 number
    - Contains at least 1 lowercase letter
    - Is at least 8 characters long

    Args:
    password (str): The password to validate.

    Returns:
    bool: True if the password meets the guidelines, False otherwise.
    """
    # Check if password is at least 8 characters long
    if len(password) < 8:
        raise PasswordFormatError()
    # Check if password contains at least 1 symbol, 1 capital letter, 1 number, and 1 lowercase letter
    if not re.search(r"[!@#$%^&*()_+{}\[\]:;<>,.?/~`\-|=]", password):
        raise PasswordFormatError()  # No symbol found
    if not re.search(r"[A-Z]", password):
        raise PasswordFormatError()  # No capital letter found
    if not re.search(r"\d", password):
        raise PasswordFormatError()  # No number found
    if not re.search(r"[a-z]", password):
        raise PasswordFormatError()  # No lowercase letter found

    return True


def hash_password(plain_password: str) -> bytes:
    """
    Hash the provided plain text password using bcrypt.

    Args:
        plain_password (str): The plain text password to be hashed.

    Returns:
        bytes: The hashed password.
    """
    salt = bcrypt.gensalt(rounds=15)
    hashed_password = bcrypt.hashpw(plain_password.encode(), salt)
    return hashed_password


def verify_password(plain_password: str, hashed_password: bytes) -> bool:
    """
    Verify if the provided plain password matches the hashed password.

    Args:
        plain_password (str): The plain text password to be verified.
        hashed_password (bytes): The hashed password against which the plain password is to be checked.

    Returns:
        bool: True if the plain password matches the hashed password, False otherwise.
    """
    return bcrypt.checkpw(plain_password.encode(), hashed_password)


def generate_access_token(payload: dict) -> str:
    """
    Generate a JWT access token with the provided payload.

    Args:
        payload (dict): The payload to be included in the token.

    Returns:
        str: The generated JWT access token.
    """
    expire = datetime.utcnow() + timedelta(minutes=TOKEN_EXPIRE_MINUTES)
    payload.update({'exp': expire})
    encoded_data = jwt.encode(payload=payload,
                              key=jwt_secret_key,
                              algorithm=ALGORITHM)

    return encoded_data


def decode_access_token(token: str) -> dict:
    """
    Decode the provided JWT access token and return its payload.

    Args:
        token (str): The JWT access token to be decoded.

    Returns:
        dict: The payload contained in the decoded JWT access token.
    """
    payload = jwt.decode(jwt=token,
                         key=jwt_secret_key,
                         algorithms=[ALGORITHM])

    return payload


def connect_to_mongo(host: str = None, port: str = None,
                     username: str = None, password: str = None,
                     database: str = None, auth_db: str = None) -> None:
    """
    Connect to the MongoDB server.

    Args:
        host (str): The MongoDB server host.
        port (int): The MongoDB server port.
        username (str): The username for authentication.
        password (str): The password for authentication.
        database (str): The name of the MongoDB database.
        auth_db (str): The authentication database.
    """
    if database is None:
        raise ValueError("Database name is required.")

    try:
        uri = f"mongodb://{host}:{port}/{database}?authSource={auth_db}"
        if username and password:
            uri = f"mongodb://{username}:{password}@{host}:{port}/{database}" \
                  f"?authSource={auth_db}&authMechanism=SCRAM-SHA-256&"

        connect(host=uri)
        print("Connected to MongoDB.")
    except Exception as ee:
        print("An unexpected error occurred while connecting to MongoDB.")
        raise ee
