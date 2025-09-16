from secrets import compare_digest
from typing import Optional

from fastapi import HTTPException, Request, Response, status
from fastapi.openapi.models import APIKey, APIKeyIn
from fastapi.security import APIKeyCookie
from fastapi.security.api_key import APIKeyBase
from pydantic import ConfigDict, BaseModel, Field

from scripts.constants.env_config import Service
from scripts.constants import Secrets
from scripts.db_connections.redis_connection import login_db
from scripts.logging.logging import logger
from scripts.utils.security_utils.apply_encryption_utility import create_token
from scripts.utils.security_utils.jwt_util import JWT


class CookieAuthentication(APIKeyBase):
    """
    Authentication backend using a cookie.
    Internally, uses a JWT token to store the data.
    """

    scheme: APIKeyCookie
    cookie_name: str
    cookie_secure: bool

    def __init__(
        self,
        cookie_name: str = "login-token",
    ):
        super().__init__()
        self.model: APIKey = APIKey(**{"in": APIKeyIn.cookie}, name=cookie_name)
        self.scheme_name = self.__class__.__name__
        self.cookie_name = cookie_name
        self.scheme = APIKeyCookie(name=self.cookie_name, auto_error=False)
        self.login_redis = login_db
        self.jwt = JWT()

    async def __call__(self, request: Request, response: Response) -> str:
        cookies = request.cookies
        login_token = cookies.get("login-token")
        if not login_token:
            login_token = request.headers.get("login-token")
        if not login_token:
            raise HTTPException(status_code=401)

        jwt_token = self.login_redis.get(login_token)
        # logger.debug(f'jwt token: {jwt_token}')
        if not jwt_token:
            raise HTTPException(status_code=401)

        try:
            decoded_token = self.jwt.validate(token=jwt_token)
            if not decoded_token:
                raise HTTPException(status_code=401)
        except Exception as e:
            logger.debug(f"Exception in decoded token: {str(e)}")
            raise HTTPException(status_code=401, detail=e.args)

        user_id = decoded_token.get("user_id")
        project_id = decoded_token.get("project_id")

        cookie_user_id = request.cookies.get("user_id", request.cookies.get("userId", request.headers.get("userId")))

        _token = decoded_token.get("token")
        _age = int(decoded_token.get("age", Secrets.LOCK_OUT_TIME_MINS))
        if not compare_digest(Secrets.token, _token):
            raise HTTPException(status_code=401)
        if login_token != decoded_token.get("uid"):
            raise HTTPException(status_code=401)

        if cookie_user_id and not compare_digest(user_id, cookie_user_id):
            raise HTTPException(status_code=401)

        try:
            new_token = create_token(
                user_id=user_id,
                ip=request.client.host,
                token=Secrets.token,
                age=_age,
                login_token=login_token,
                project_id=project_id,
            )
        except Exception as e:
            logger.debug(f"Exception in create token: {str(e)}")
            raise HTTPException(status_code=401, detail=e.args)
        response.set_cookie(
            "login-token",
            new_token,
            samesite="strict",
            httponly=True,
            secure=Service.secure_cookie,
            max_age=Secrets.LOCK_OUT_TIME_MINS * 60,
        )
        response.headers["login-token"] = new_token

        # If project ID is null, this is susceptible to 500 Status Code. Ensure token formation has project ID in
        # # login token
        response.headers.update(
            {
                "login-token": new_token,
                "projectId": project_id,
                "project_id": project_id,
                "userId": user_id,
                "user_id": user_id,
            }
        )
        return user_id


class MetaInfoSchema(BaseModel):
    projectId: Optional[str] = ""
    project_id: Optional[str] = ""
    user_id: Optional[str] = ""
    language: Optional[str] = ""
    ip_address: Optional[str] = ""
    login_token: Optional[str] = Field("", alias="login-token")
    model_config = ConfigDict(populate_by_name=True)


class MetaInfoCookie(APIKeyBase):
    """
    Project ID backend using a cookie.
    """

    scheme: APIKeyCookie

    def __init__(self):
        super().__init__()
        self.model: APIKey = APIKey(**{"in": APIKeyIn.cookie}, name="meta")
        self.scheme_name = self.__class__.__name__

    def __call__(self, request: Request, response: Response):
        cookies = request.cookies
        cookie_json = {
            "projectId": cookies.get("projectId", request.headers.get("projectId")),
            "userId": cookies.get("user_id", cookies.get("userId", request.headers.get("userId"))),
            "language": cookies.get("language", request.headers.get("language")),
        }
        return MetaInfoSchema(
            project_id=cookie_json["projectId"],
            user_id=cookie_json["userId"],
            projectId=cookie_json["projectId"],
            language=cookie_json["language"],
            ip_address=request.client.host,
            login_token=cookies.get("login-token"),
        )


class GetUserID(APIKeyBase):
    """
    Project ID backend using a cookie.
    """

    scheme: APIKeyCookie

    def __init__(self):
        super().__init__()
        self.model: APIKey = APIKey(**{"in": APIKeyIn.cookie}, name="user_id")
        self.scheme_name = self.__class__.__name__

    def __call__(self, request: Request, response: Response):
        if user_id := request.cookies.get("user_id", request.cookies.get("userId", request.headers.get("userId"))):
            return user_id
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)
