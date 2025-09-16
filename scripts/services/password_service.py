from fastapi import APIRouter, Request, Depends
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from scripts.constants.api_endpoints import APIEndPoints

from scripts.db_connections.psql.database_engine import get_db
from scripts.handlers.traveller_login import TravellerLoginHandler
from scripts.logging.logging import logger

password_router = APIRouter(prefix=APIEndPoints.base_proxy_traveller, tags=["Login"], include_in_schema=False)


@password_router.post(APIEndPoints.api_forgot_password, include_in_schema=False)
def change_password(email: str, old_password: str, new_password: str, db: Session = Depends(get_db)):
    """
    The forgot_password_web function is used to send a password reset email to the user.
        It takes in an input_data object of type ForgotPasswordRequest, which contains the following fields:
            - email (str): The user's email address.

    :param request: Request: Get the request object from fastapi
    :param input_data: ForgotPasswordRequest: Validate the request body
    :return: A jsonresponse object with the status and message keys
    """
    try:
        traveller_login_handler = TravellerLoginHandler(db=db)
        resp = traveller_login_handler.forgot_password(email, old_password, new_password)
        return resp
    except Exception as e:
        logger.exception(str(e))
        return JSONResponse({"status": "failed", "message": str(e)})
