import json
import time
from datetime import datetime

import shortuuid

from scripts.constants import Secrets
from scripts.constants.env_config import Security
from scripts.db_connections.psql.query_layer.organizer_login import OrganizerQueryLayer
from scripts.db_connections.redis_connection import login_db
from scripts.errors import InvalidPasswordError, IllegalToken
from scripts.errors.exception_codes import DefaultExceptionsCode
from scripts.logging.logging import logging
from sqlalchemy.orm import Session
import bcrypt
from fastapi import Request, Response

from scripts.schemas.organizer_login_schema import OrganizerLoginRequest, OrganizerRegisterRequest
from scripts.utils.security_utils.aes_enc import AESCipher
from scripts.utils.security_utils.apply_encryption_utility import create_token


class OrganizerLoginHandler:
    def __init__(self, db: Session):
        self.organizer_query_layer = OrganizerQueryLayer(db)
        self.login_redis = login_db
        self.permanent_token = Secrets.token

    def register_organizer(self, request_data: OrganizerRegisterRequest):
        try:
            existing_organizer = self.organizer_query_layer.get_user_by_email(request_data.email)
            if existing_organizer and existing_organizer.email == request_data.email:
                return {"status": "Failed", "message": f"Email {request_data.email} is already registered."}
            if existing_organizer and existing_organizer.contact_number == request_data.contact_number:
                raise {"status": "Failed", "message": f"Phone number {request_data.contact_number} is already in use."}
            hash_pass = bcrypt.hashpw(request_data.password.encode("utf-8"), bcrypt.gensalt())
            hashed_password = hash_pass.decode("utf-8")  # Convert bytes → str for storage

            # Update the password in input data
            request_data.password = hashed_password
            request_data.user_id = self.organizer_query_layer.create_user(request_data.model_dump())
            new_profile = self.organizer_query_layer.create_organizer_profile(request_data.model_dump())
            if request_data.user_id and new_profile:
                return {"status": 200, "message": "Traveller registered successfully. Please login into system"}
            else:
                return {"status": 500, "message": "Error in registering traveller."}
        except Exception as e:
            logging.exception(f"Exception during traveller registration: {str(e)}")
            raise

    def get_secret_key(self, token, username, unique_key):
        logging.info("Fetching token to decrypt")
        if token != self.permanent_token:
            raise IllegalToken
        return username[:3] + unique_key

    def validate_password(self, username, password, user_record, token, enc, unique_key=None):
        try:
            if enc:
                secret_key = self.get_secret_key(token=token, username=username, unique_key=unique_key)
                password = AESCipher(key=secret_key).decrypt(password)
        except Exception as e:
            logging.exception(e)
            raise
        if not user_record.get("password") or user_record.get("password") == "null":
            raise InvalidPasswordError(msg=DefaultExceptionsCode.DEIL)
        if not bcrypt.checkpw(password.encode("utf-8"), user_record["password"].encode("utf-8")):
            raise InvalidPasswordError(msg=DefaultExceptionsCode.DEIP)
        return True

    @staticmethod
    def set_login_token(response, user_record, client_ip, token, lockout_time):
        login_token = create_token(
            user_id=user_record.get("user_id"),
            ip=client_ip,
            token=token,
            age=lockout_time,
        )
        logging.info(f"space_id while creating login token {login_token}")
        response.set_cookie(
            "login-token",
            login_token,
            samesite="strict",
            httponly=True,
            max_age=lockout_time * 60,
            secure=Security.SECURE_COOKIE,
        )
        response.headers["login-token"] = login_token

    def common_method_login_token(
        self, response, user_record, client_ip, token
    ):
        refresh_age = Security.REFRESH_TOKEN_DURATION
        refresh_token = create_token(
            user_id=user_record.get("user_id"), ip=client_ip, token=token, age=refresh_age * 60
        )
        response.set_cookie(
            "refresh-token",
            refresh_token,
            samesite="strict",
            httponly=True,
            max_age=refresh_age * 60 * 60,
            secure=Security.SECURE_COOKIE,
        )
        lockout_time = Security.LOCK_OUT_TIME_MINS
        self.set_login_token(
            response, user_record, client_ip, token, lockout_time
        )
        login_exp_time = str(int(time.time() + lockout_time * 60) * 1000)
        response.set_cookie(
            "login_exp_time",
            login_exp_time,
            samesite="strict",
            httponly=True,
            max_age=Security.LOCK_OUT_TIME_MINS * 60,
            secure=Security.SECURE_COOKIE,
        )

        response.set_cookie(
            "user_id",
            user_record.get("user_id"),
            httponly=True,
            secure=Security.SECURE_COOKIE,
        )
        response.set_cookie(
            "userId",
            user_record.get("user_id"),
            httponly=True,
            secure=Security.SECURE_COOKIE,
        )
        response.headers.update(
            {
                "refresh-token": refresh_token,
                "login_exp_time": login_exp_time,
            }
        )

        response.set_cookie(
            "language",
            user_record.get("language", "en"),
            httponly=True,
            secure=Security.SECURE_COOKIE,
        )

    def handle_login(self, request_data: OrganizerLoginRequest, request: Request, response: Response, token: str, enc=True):
        try:
            user_record = self.organizer_query_layer.get_user_by_email(email=request_data.user_name)

            unique_key = request.cookies.get("unique-key", request.headers.get("unique-key"))
            auth = self.validate_password(
                username=request_data.user_name,
                password=request_data.password,
                user_record=user_record.to_dict(),
                token=token,
                enc=enc,
                unique_key=unique_key,
            )
            if not auth:
                raise InvalidPasswordError(msg=DefaultExceptionsCode.DEIP)
            client_ip = request.client.host
            # Login Response
            final_json = {**user_record.to_dict(exclude=["password", "passport_number", "created_at", "updated_at", "last_logged_at"])}
            self.common_method_login_token(
                response=response,
                user_record=user_record.to_dict(),
                client_ip=client_ip,
                token=token,
            )
            self.organizer_query_layer.update_user(
                update_data={"last_logged_at": datetime.now()},
                query={"user_id": user_record.user_id},
            )
            return final_json
        except Exception as e:
            logging.exception(f"Exception during traveller login: {str(e)}")
            raise

    def get_token(self, response: Response, t: str = None, is_service=False):
        authentication_token = shortuuid.ShortUUID().random(length=13)
        response.set_cookie("token", self.permanent_token, httponly=True, secure=Security.SECURE_COOKIE)
        response.set_cookie(
            "unique-key",
            authentication_token,
            httponly=True,
            max_age=300,
            secure=Security.SECURE_COOKIE,
        )
        response.headers["unique-key"] = authentication_token
        response = {
            "unique_key": authentication_token,
            "token": self.permanent_token,
            "verify_signature": Security.VERIFY_SIGNATURE,
            "status": "success",
        }
        if is_service:
            response.pop("token", None)
        if t and isinstance(t, str) and t.lower() == "constants":
            response["c_key"] = shortuuid.ShortUUID().random(length=13)
        return response

    def logout(self, session_id, login_token, refresh_token):
        final_json = {"status": "failed", "message": "Logout failed"}
        try:
            logging.debug(session_id)
            final_json["status"] = "success"
            final_json["message"] = "Logout Successfully"
            resp = Response(content=json.dumps(final_json), media_type="application/json")
            resp.set_cookie("session_id", "", expires=0, secure=Security.SECURE_COOKIE, httponly=Security.HTTP_FLAG)
            resp.set_cookie("user_id", "", expires=0, secure=Security.SECURE_COOKIE, httponly=Security.HTTP_FLAG)
            resp.set_cookie("login-token", "", expires=0, secure=Security.SECURE_COOKIE, httponly=Security.HTTP_FLAG)
            resp.set_cookie("userId", "", expires=0, secure=Security.SECURE_COOKIE, httponly=Security.HTTP_FLAG)
            resp.set_cookie("refresh-token", "", expires=0, secure=Security.SECURE_COOKIE, httponly=Security.HTTP_FLAG)
            self.login_redis.delete(login_token)
            self.login_redis.delete(refresh_token)
            return resp
        except Exception as e:
            logging.exception(f"Exception while logging out ->{str(e)}")
            return final_json