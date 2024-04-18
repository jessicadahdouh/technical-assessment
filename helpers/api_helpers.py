from helpers.db_helpers import insert_user, get_user, edit_record, delete_record
from helpers.utils import verify_password, hash_password, decode_access_token
from fastapi import HTTPException, Header
from models.schemas import User
from typing import Tuple
import jwt


def create_user(user: User):
    # Hash the password
    b_hash = hash_password(plain_password=user.password)

    user.password = b_hash

    # Insert the user into the database
    return insert_user(record=user)


def verify_token(authorization: str = Header(...), admin: bool = False) -> str:
    """
    Extract and verify JWT access token from request headers.

    Args:
        authorization (str): The authorization header containing the token.
        admin (bool): Whether the user is an admin or not.

    Returns:
        str: The verified token.

    Raises:
        HTTPException: Raised for authorization header issues, expired tokens, invalid tokens,
                       non-admin users trying to access admin endpoints, and other errors.
    """
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Authorization header is missing or malformed")

    token = authorization.split("Bearer ")[1]
    try:
        payload = decode_access_token(token)
        username = payload.get("username")
        user = get_user(username)

        if user is None:
            raise HTTPException(status_code=404, detail="User doesn't exist")

        if admin:
            if not user.is_admin:
                raise HTTPException(status_code=401, detail="User is not an admin")

            if not payload.get("is_admin"):
                raise HTTPException(status_code=401, detail="Invalid token: admin claim is not True")

    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=403, detail="Token has expired.")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Unauthorized access: Invalid token.")

    return token


def get_admin_token(authorization: str = Header(...)) -> str:
    """
    Extract and verify admin token from request headers.

    Args:
        authorization (str): The authorization header containing the token.

    Returns:
        str: The verified admin token.

    Raises:
        HTTPException: Raised for authorization header issues, expired tokens, invalid tokens,
                       and non-admin users trying to access admin endpoints.
    """
    return verify_token(authorization, admin=True)


def get_user_token(authorization: str = Header(...)) -> str:
    """
    Extract and verify user token from request headers.

    Args:
        authorization (str): The authorization header containing the token.

    Returns:
        str: The verified user token.

    Raises:
        HTTPException: Raised for authorization header issues, expired tokens, and invalid tokens.
    """
    return verify_token(authorization, admin=False)


def validate_credentials(username: str, password: str) -> Tuple[bool, User]:
    """
    Check if the provided credentials (username and password) are valid.

    Args:
        username (str): The username of the user.
        password (str): The password to validate.

    Returns:
        Tuple[bool, User]: A tuple containing the validity of the password and the user object.
            - The first element is a boolean indicating whether the password is valid.
            - The second element is a user object representing the user if found.

    Raises:
        HTTPException: Raised if the user doesn't exist.
    """
    user = get_user(username)

    if user is None:
        raise HTTPException(status_code=404, detail="User doesn't exist!")

    # Validate the provided password against the hashed password stored in the database
    validity = verify_password(plain_password=password, hashed_password=user.password)

    return validity, user


def get_user_from_token(token: str):
    """
    Retrieve user information based on the access token.

    Args:
        token (str): The access token used to identify the user.
    """
    payload = decode_access_token(token)
    user = get_user(payload.get('username', None))
    return user


def update_user(username: str, user: User) -> bool:
    """Update the user information."""
    # Hash the password
    b_hash = hash_password(plain_password=user.password)

    user.password = b_hash

    return edit_record(old_user=username, record=user)


def delete_db_user(username: str) -> bool:
    """Delete the user."""
    return delete_record(username=username)
