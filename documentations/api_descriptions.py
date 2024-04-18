create_user_desc = """
    Create a new user with the given username and password.

    Args:
        request_data (dict): A JSON object containing the request data with the following keys:
            - "username" (str):
            - "password" (str):
            - "is_admin" (bool):
        token (str): sent in header of request.
    """

create_admin_desc = """
    Create an admin user with the given username and password.

    Args:
        request_data (dict) containing:
            username (str): The username of the user.
            password (str): The password of the user.
            is_admin (bool): If the user is an admin or not.
    """

login_desc = """
    Authenticate a user and generate an access token.

    Args:
        request_data (dict): The request body containing:
            - username (str)
            - password (str)

    Returns:
        A JSON response containing the status of the authentication attempt and the generated access token.
    """

get_user_info_desc = """
    Retrieve user information based on the access token.
    
    Args:
       token (str): The access token used to authenticate the user (found in header).
    
    Returns:
       A JSON response containing the user information if the token is valid, otherwise an error message.
    """

edit_user_desc = """
    Edit a user record.

    Args:
        request_data (User): The updated user record containig.
        token (str): The access token used to authenticate the user.
    """

delete_user_desc = """
    Delete the user associated with the provided access token from the database.

    Args:
        token (str): The access token used to authenticate the user.
    """