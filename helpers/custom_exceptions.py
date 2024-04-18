class UserAlreadyExistsError(Exception):
    """Exception raised when attempting to insert a user that already exists."""

    def __init__(self, username):
        self.username = username
        super().__init__(f"User '{username}' already exists")


class PasswordFormatError(Exception):
    """Custom exception raised when the password format is incorrect."""
    def __init__(self):
        message = "Password format is incorrect. " \
                  "It should contain at least " \
                  "1 symbol, " \
                  "1 capital letter, " \
                  "1 number, " \
                  "1 lowercase letter, and be at least " \
                  "8 characters long."
        super().__init__(message)
