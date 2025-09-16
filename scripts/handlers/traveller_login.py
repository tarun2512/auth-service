import json
import time

import shortuuid
from datetime import datetime


from scripts.constants import Secrets
from scripts.constants.env_config import Security
from scripts.db_connections.psql.query_layer.traveller_login import TravellerQueryLayer
from scripts.db_connections.redis_connection import login_db
from scripts.errors import InvalidPasswordError, IllegalToken
from scripts.errors.exception_codes import DefaultExceptionsCode
from scripts.logging.logging import logging
from sqlalchemy.orm import Session
import bcrypt
from fastapi import Request, Response
from scripts.schemas.traveller_login_schema import TravellerRegister, TravellerLogin
from scripts.utils.security_utils.aes_enc import AESCipher
from scripts.utils.security_utils.apply_encryption_utility import create_token


class TravellerLoginHandler:
    def __init__(self, db: Session):
        self.traveller_query_layer = TravellerQueryLayer(db)
        self.login_redis = login_db
        self.permanent_token = Secrets.token

    async def register_traveller(self, request_data: TravellerRegister):
        try:
            existing_user = self.traveller_query_layer.get_user_by_email(request_data.email)
            if existing_user and existing_user.email == request_data.email:
                return {"status": "Failed", "message": f"Email {request_data.email} is already registered."}
            if existing_user and existing_user.contact_number == request_data.contact_number:
                raise {"status": "Failed", "message": f"Phone number {request_data.contact_number} is already in use."}
            hash_pass = bcrypt.hashpw(request_data.password.encode("utf-8"), bcrypt.gensalt())
            hashed_password = hash_pass.decode("utf-8")  # Convert bytes → str for storage

            # Update the password in input data
            request_data.password = hashed_password
            request_data.user_id = shortuuid.uuid()
            self.traveller_query_layer.create_user(request_data.model_dump())
            request_data.traveller_id = shortuuid.uuid()
            new_profile = self.traveller_query_layer.create_traveller_profile(request_data.model_dump())
            if request_data.user_id and new_profile:
                return {"status": "success", "message": "Traveller registered successfully. Please login into system"}
            else:
                return {"status": "Failed", "message": "Error in registering traveller."}
        except Exception as e:
            logging.exception(f"Exception during traveller registration: {str(e)}")
            raise

    def get_secret_key(self, token, username, unique_key):
        logging.info("Fetching token to decrypt")
        if token != self.permanent_token:
            raise IllegalToken
        return username[3:] + unique_key

    def validate_password(self, email, password, user_record, token, enc, unique_key=None):
        try:
            if enc:
                secret_key = self.get_secret_key(token=token, username=email, unique_key=unique_key)
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
        try:
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
        except Exception as e:
            logging.exception(f"Exception in common_method_login_token: {str(e)}")
            raise

    def handle_login(self, request_data: TravellerLogin, request: Request, response: Response, token: str, enc=True):
        try:
            user_record = self.traveller_query_layer.get_user_by_email(email=request_data.email)

            unique_key = request.cookies.get("unique-key", request.headers.get("unique-key"))
            auth = self.validate_password(
                email=request_data.email,
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
            self.traveller_query_layer.update_user(
                update_data={"last_logged_at": datetime.now()},
                query={"user_id": user_record.user_id},
            )
            return final_json
        except Exception as e:
            logging.exception(f"Exception during traveller login: {str(e)}")
            raise

    def get_token(self, response: Response, t: str = None):
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
            resp.set_cookie("projectId", "", expires=0, secure=Security.SECURE_COOKIE, httponly=Security.HTTP_FLAG)
            resp.set_cookie("refresh-token", "", expires=0, secure=Security.SECURE_COOKIE, httponly=Security.HTTP_FLAG)
            self.login_redis.delete(login_token)
            self.login_redis.delete(refresh_token)
            return resp
        except Exception as e:
            logging.exception(f"Exception while logging out ->{str(e)}")
            return final_json

    def forgot_password(self, email, old_password, new_password):
        try:
            user_record = self.traveller_query_layer.get_user_by_email(email=email)
            if not user_record or user_record.email != email:
                return {"status": "failed", "message": f"Email {email} not registered."}
            if not bcrypt.checkpw(old_password.encode("utf-8"), user_record.password.encode("utf-8")):
                return {"status": "failed", "message": "Old password is incorrect."}
            hash_pass = bcrypt.hashpw(new_password.encode("utf-8"), bcrypt.gensalt())
            hashed_password = hash_pass.decode("utf-8")  # Convert bytes → str for storage
            update_status = self.traveller_query_layer.update_user(
                update_data={"password": hashed_password},
                query={"email": email},
            )
            if update_status:
                return {"status": 200, "message": "Password updated successfully. Please login into system"}
            else:
                return {"status": 500, "message": "Error in updating password."}
        except Exception as e:
            logging.exception(f"Exception during password change: {str(e)}")
            raise