from typing import Optional

from fastapi import (
    APIRouter,
    Depends,
    Request,
    Response, HTTPException, Cookie
)
from sqlalchemy.orm import Session

from scripts.constants.api_endpoints import APIEndPoints
from scripts.constants.env_config import Security
from scripts.errors import TooManyRequestsError
from scripts.errors.exception_codes import DefaultExceptionsCode
from scripts.handlers.traveller_login import TravellerLoginHandler
from scripts.db_connections.psql.database_engine import get_db
from scripts.logging.logging import logger
from scripts.schemas.response_models import (
    DefaultFailureResponse,
    DefaultSuccessResponse, GetTokenResponse,
)
from scripts.schemas.traveller_login_schema import TravellerRegister, TravellerLogin
from scripts.utils.security_utils.decorators import MetaInfoCookie, MetaInfoSchema
from scripts.utils.security_utils.decorators import CookieAuthentication


traveller_login_router = APIRouter(prefix=APIEndPoints.base_proxy_traveller, tags=["Step services"])
auth = CookieAuthentication()
get_cookies = MetaInfoCookie()
task_audit_logs_entity = "tasks"
data_explorer_audit_logs_entity = "dataExplorerV2"



@traveller_login_router.post(
    APIEndPoints.api_register,
    response_model=DefaultSuccessResponse,
)
async def register_traveller(
    request_data: TravellerRegister,
    db: Session = Depends(get_db),
):
    """
    The get_audit_logs_headers function is used to get the audit logs headers.

    :param request_data: dict: Decode the request parameters
    :param meta: MetaInfoSchema: Get the project_id from the cookies
    :param db: Session: Pass the database connection to the function
    :param : Get the audit logs for a particular user
    :return: The audit logs headers
    """
    try:
        traveller_login_handler = TravellerLoginHandler(db=db)
        result = await traveller_login_handler.register_traveller(request_data=request_data)
        return DefaultSuccessResponse(
            status=result.get("status"), message=result.get("message"), data=None
        ).dict()
    except Exception as e:
        logger.exception(e)
        return DefaultFailureResponse(error=e.args)


@traveller_login_router.post(APIEndPoints.api_login)
def login(
    request_data: TravellerLogin,
    request: Request,
    response: Response,
    token: str = Cookie(...),
    db: Session = Depends(get_db),
):
    """
    This API is used to validate the username and password and provide required authentication to the user
    """
    try:
        logger.info(f"HOST - {request.client.host}\nHOST - {request.headers.get('host')}")
        traveller_login_handler = TravellerLoginHandler(db=db)
        resp = traveller_login_handler.handle_login(
            request_data=request_data,
            request=request,
            response=response,
            token=token,
            enc=not Security.DISABLE_ENC,
        )
        return DefaultSuccessResponse(
            status="success", message="Logged in Successfully", data=resp
        ).dict() or {"status": "failed", "message": DefaultExceptionsCode.DE001}
    except TooManyRequestsError as e:
        raise HTTPException(
            status_code=429,
            detail=e.args,
        )
    except Exception as e:
        logger.exception(f"Error while logging - f{str(e)}")
        raise HTTPException(
            status_code=401,
            detail=e.args,
        ) from e


@traveller_login_router.get(APIEndPoints.api_get_token, response_model=GetTokenResponse)
def get_token(response: Response, t: Optional[str] = None,     db: Session = Depends(get_db)):
    """
    API to set token and unique key in headers/cookie
    """
    traveller_login_handler = TravellerLoginHandler(db=db)
    return traveller_login_handler.get_token(response, t=t)


@traveller_login_router.get(APIEndPoints.api_logout)
def logout(request: Request, db: Session = Depends(get_db)):
    """
    API to log out the user session of the logged-in user
    """
    try:
        session_id = request.cookies.get("session_id")
        login_token = request.cookies.get("login-token")
        if login_token is None:
            login_token = request.headers.get("login-token")
        refresh_token = request.cookies.get("refresh-token")
        if refresh_token is None:
            refresh_token = request.headers.get("refresh-token")
        traveller_login_handler = TravellerLoginHandler(db=db)
        return traveller_login_handler.logout(session_id, login_token, refresh_token)
    except Exception as e:
        return DefaultFailureResponse(message="Failed to logout", error=str(e)).model_dump()