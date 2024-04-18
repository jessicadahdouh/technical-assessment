from Crypto.Random import get_random_bytes
import secrets


def generate_jwt_key():
    """
    Generates a random secret key with 32 bytes (256 bits)

    Returns:
        str: The generated random key.
    """
    jwt_secret_key = secrets.token_hex(32)
    return jwt_secret_key


def generate_key_hex():
    """Generates a random 256-bit key and returns its hexadecimal representation.

    Returns:
        str: The hexadecimal representation of the generated random key.
    """
    secret_key = get_random_bytes(32)  # 256-bit key as a binary string
    return secret_key.hex()


print("Generated JWT secret key:", generate_jwt_key())
print("Generated secret key:", generate_key_hex())



