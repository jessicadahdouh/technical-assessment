from documentations.api_descriptions import login_desc
from helpers.api_helpers import validate_credentials
from helpers.response_format import http_response
from helpers.db_helpers import save_access_token
from helpers.utils import generate_access_token
from fastapi import APIRouter, Body


router = APIRouter()


@router.post('/login', description=login_desc)
def create_token(request_data: dict = Body(...)):
    """
    Authenticate a user and generate an access token.

    Args:
        request_data (dict): The request body containing:
            - username (str)
            - password (str)

    Returns:
        A JSON response containing the status of the authentication attempt and the generated access token.
    """
    try:
        username = request_data.get("username")
        password = request_data.get("password")

        valid, user_info = validate_credentials(username, password)
        result = {
                    "status": True,
                    "data": {},
                    "extras": {},
                    "response_code": 1,
                    "title": "Create Token",
                    "message": "",
                    "developer_message": "",
                    "total_count": None
                }
        if valid:
            # Generate access token
            access_token = generate_access_token({"username": user_info.username, "is_admin": user_info.is_admin})

            result["data"] = {
                                "user_access_token": access_token
                            }
            save_access_token(username=user_info.username, user_access_token=access_token)
            return http_response(data=result, status_code=200)
        else:
            result["status"] = False
            result["response_code"] = 2
            result["message"] = "Invalid username or password"
            return http_response(data=result, status_code=401)
    except Exception as e:
        result = {
            "status": False,
            "data": {},
            "extras": {},
            "response_code": 3,
            "title": "Create Token",
            "message": "An error occurred while creating the token.",
            "developer_message": str(e),
            "total_count": None
        }
        return http_response(data=result, status_code=500)
