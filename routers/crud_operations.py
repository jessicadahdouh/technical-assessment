from documentations.api_descriptions import create_user_desc, create_admin_desc, get_user_info_desc, edit_user_desc, \
    delete_user_desc
from helpers.api_helpers import create_user, get_admin_token, get_user_from_token, get_user_token, update_user, \
    delete_db_user
from helpers.custom_exceptions import UserAlreadyExistsError, PasswordFormatError
from helpers.utils import generate_access_token, validate_password
from helpers.response_format import http_response
from fastapi import Depends, Body
from models.schemas import User
from fastapi import APIRouter


router = APIRouter()


@router.get('/get_user_info', description=get_user_info_desc)
def get_user_info(token: str = Depends(get_user_token)):
    """
    Retrieve user information based on the access token.

    Args:
       token (str): The access token used to authenticate the user (found in header).

    Returns:
       A JSON response containing the user information if the token is valid, otherwise an error message.
    """
    result = {
                "status": True,
                "data": {
                },
                "extras": {},
                "response_code": 1,
                "title": "User info",
                "message": "",
                "developer_message": "",
                "total_count": 1
            }
    if token is None:
        result["status"] = False
        result["response_code"] = 2
        result["developer_message"] = "Access token is missing."
        return http_response(data=result, status_code=401)

    user_info = get_user_from_token(token)
    if user_info is None:
        result["status"] = False
        result["response_code"] = 2
        result["developer_message"] = "Invalid access token."
        return http_response(data=result, status_code=401)

    result["data"] = {
                        'username': user_info.username,
                        'is_admin': user_info.is_admin,
                        'user_access_token': user_info.access_token
                    }
    return http_response(data=result, status_code=200)


@router.post('/create_admin_user', description=create_admin_desc)
def create_admin_user(request_data: User = Body(...)):
    """
    Create an admin user with the given username and password.

    Args:
        request_data (dict) containing:
            username (str): The username of the user.
            password (str): The password of the user.
            is_admin (bool): If the user is an admin or not.
    """
    try:
        response = create_user(request_data)
        data = {"username": request_data.username, "is_admin": request_data.is_admin}
        access_token = generate_access_token(payload=data)
        if response == True:
            result = {
                "status": True,
                "data": {
                    'admin_access_token': access_token
                },
                "extras": {},
                "response_code": 1,
                "title": "Create Admin User",
                "message": "",
                "developer_message": "User inserted successfully.",
                "total_count": 1
            }
            return http_response(data=result, status_code=201)
        elif response == 'Found':
            raise UserAlreadyExistsError(request_data.username)

    except UserAlreadyExistsError as old_user:
        response = {
                    "status": False,
                    "data": {},
                    "extras": {},
                    "response_code": 2,
                    "title": "Create Admin User",
                    "message": str(old_user),
                    "developer_message": "Conflict: User exists!",
                    "total_count": None
                }
        return http_response(data=response, status_code=409)
    except Exception as e:
        response = {
            "status": False,
            "data": {},
            "extras": {},
            "response_code": 3,
            "title": "Create Admin User",
            "message": "An error occurred.",
            "developer_message": str(e),
            "total_count": None
        }
        return http_response(data=response, status_code=500)


@router.post('/create_user', description=create_user_desc)
def create_new_user(request_data: User = Body(...),
                    token: str = Depends(get_admin_token)):
    """
    Create a new user with the given username and password.

    Args:
        request_data (dict): A JSON object containing the request data with the following keys:
            - "username" (str):
            - "password" (str):
            - "is_admin" (bool):
        token (str): sent in header of request.
    """
    try:
        validate_password(request_data.password)
        response = create_user(request_data)
        if response == True:
            result = {
                "status": True,
                "data": {},
                "extras": {},
                "response_code": 1,
                "title": "Create User",
                "message": "",
                "developer_message": "User inserted successfully.",
                "total_count": 1
            }
            return http_response(data=result, status_code=201)
        elif response == 'Found':
            raise UserAlreadyExistsError(request_data.username)
    except PasswordFormatError as invalid_pass:
        response = {
            "status": False,
            "data": {},
            "extras": {},
            "response_code": 2,
            "title": "Create User",
            "message": str(invalid_pass),
            "developer_message": "Invalid Password.",
            "total_count": None
        }
        return http_response(data=response, status_code=400)
    except UserAlreadyExistsError as old_user:
        response = {
                    "status": False,
                    "data": {},
                    "extras": {},
                    "response_code": 2,
                    "title": "Create User",
                    "message": str(old_user),
                    "developer_message": "Conflict: User exists!",
                    "total_count": None
                }
        return http_response(data=response, status_code=409)
    except Exception as e:
        response = {
            "status": False,
            "data": {},
            "extras": {},
            "response_code": 3,
            "title": "Create User",
            "message": "An error occurred.",
            "developer_message": str(e),
            "total_count": None
        }
        return http_response(data=response, status_code=500)


@router.put('/edit_user', description=edit_user_desc)
def edit_user(request_data: User = Body(...),
              token: str = Depends(get_user_token)):
    """
    Edit a user record.

    Args:
        request_data (User): The updated user record containig.
        token (str): The access token used to authenticate the user.
    """
    try:
        validate_password(request_data.password)
        user_info = get_user_from_token(token)

        edited = update_user(user_info.username, request_data)
        if edited == True:
            result = {
                "status": True,
                "data": {},
                "extras": {},
                "response_code": 1,
                "title": "Edit User",
                "message": "",
                "developer_message": "User edited successfully.",
                "total_count": 1
            }
            return http_response(data=result, status_code=201)
        elif edited == 'Found':
            raise UserAlreadyExistsError(request_data.username)
    except PasswordFormatError as invalid_pass:
        response = {
            "status": False,
            "data": {},
            "extras": {},
            "response_code": 2,
            "title": "Edit User",
            "message": str(invalid_pass),
            "developer_message": "Invalid Password.",
            "total_count": None
        }
        return http_response(data=response, status_code=400)
    except UserAlreadyExistsError as old_user:
        response = {
                    "status": False,
                    "data": {},
                    "extras": {},
                    "response_code": 2,
                    "title": "Edit User",
                    "message": str(old_user),
                    "developer_message": "Conflict: User exists!",
                    "total_count": None
                }
        return http_response(data=response, status_code=409)
    except Exception as e:
        response = {
            "status": False,
            "data": {},
            "extras": {},
            "response_code": 3,
            "title": "Edit User",
            "message": "An error occurred.",
            "developer_message": str(e),
            "total_count": None
        }
        return http_response(data=response, status_code=500)


@router.delete('/delete_user', description=delete_user_desc)
def delete_user(token: str = Depends(get_user_token)):
    """
    Delete the user associated with the provided access token from the database.

    Args:
        token (str): The access token used to authenticate the user.
    """
    user_info = get_user_from_token(token)
    deleted = delete_db_user(user_info.username)
    result = {
        "status": True,
        "data": {},
        "extras": {},
        "response_code": 1,
        "title": "Delete User",
        "message": "",
        "developer_message": "User deleted successfully.",
        "total_count": 1
    }
    if deleted:
        return http_response(data=result, status_code=200)
    else:
        result["status"] = False
        result["response_code"] = 3
        result["developer_message"] = "Error deleting user."
        return http_response(data=result, status_code=500)
