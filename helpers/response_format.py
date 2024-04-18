from fastapi.responses import JSONResponse
from fastapi import HTTPException
from typing import Dict, Any, Optional


response = {
            "status": True,
            "data": {},
            "extras": {},
            "response_code": 1,
            "title": "",
            "message": "",
            "developer_message": "",
            "total_count": None
            }

# response_code = 1 => success
# response_code = 2 => validation error
# response_code = 3 => error


def http_response(data: Any = None, headers: Optional[Dict[str, str]] = None, status_code: int = 200) -> JSONResponse:
    """
    Generate a secure JSON response with security-related headers.

    Args:
        data (Any, optional): The data to be included in the JSON response. Defaults to None.
        headers (Dict[str, str], optional): Custom headers to be included in the response. Defaults to None.
        status_code (int, optional): The HTTP status code for the response. Defaults to 200.

    Returns:
        JSONResponse: The generated JSON response with security-related headers.

    Raises:
        HTTPException: Raised when the input data is not provided.
    """
    if not headers:
        # Set security-related headers
        headers = {
            "Content-Type": "application/json",
            "X-Content-Type-Options": "nosniff",
            "Content-Security-Policy": "default-src 'self'",
            "X-Frame-Options": "DENY",
            "X-XSS-Protection": "1; mode=block",
        }

    try:
        # Validate input data
        if not data:
            raise HTTPException(status_code=404, detail="Data not found")

        # Return the secure JSON response
        return JSONResponse(content=data, status_code=status_code, headers=headers)

    except Exception as e:
        # Handle errors gracefully
        error_message = {"error": str(e)}
        return JSONResponse(content=error_message, status_code=500, headers=headers)
