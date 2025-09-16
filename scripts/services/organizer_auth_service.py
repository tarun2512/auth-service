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
from scripts.handlers.organizer_login import OrganizerLoginHandler
from scripts.db_connections.psql.database_engine import get_db
from scripts.logging.logging import logger
from scripts.schemas.organizer_login_schema import OrganizerRegisterRequest, OrganizerLoginRequest
from scripts.schemas.response_models import (
    DefaultFailureResponse,
    DefaultSuccessResponse, GetTokenResponse,
)
from scripts.utils.security_utils.decorators import MetaInfoCookie
from scripts.utils.security_utils.decorators import CookieAuthentication


organizer_login_router = APIRouter(prefix=APIEndPoints.base_proxy_organizer, tags=["Step services"])
auth = CookieAuthentication()
get_cookies = MetaInfoCookie()
task_audit_logs_entity = "tasks"
data_explorer_audit_logs_entity = "dataExplorerV2"



@organizer_login_router.get(
    APIEndPoints.api_register,
    response_model=DefaultSuccessResponse,
)
async def register_organizer(
    request_data: OrganizerRegisterRequest,
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
        organizer_login_handler = OrganizerLoginHandler(db=db)
        result = await organizer_login_handler.register_organizer(request_data=request_data)
        return DefaultSuccessResponse(
            status=result.get("status"), message=result.get("message"), data=None
        ).dict()
    except Exception as e:
        logger.exception(e)
        return DefaultFailureResponse(error=e.args)


@organizer_login_router.post(APIEndPoints.api_login)
def login(
    request_data: OrganizerLoginRequest,
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
        organizer_login_handler = OrganizerLoginHandler(db=db)
        resp = organizer_login_handler.handle_login(
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


@organizer_login_router.get(APIEndPoints.api_get_token, response_model=GetTokenResponse)
def get_token(response: Response, t: Optional[str] = None,     db: Session = Depends(get_db)):
    """
    API to set token and unique key in headers/cookie
    """
    organizer_login_handler = OrganizerLoginHandler(db=db)
    return organizer_login_handler.get_token(response, t=t, is_service=True)


