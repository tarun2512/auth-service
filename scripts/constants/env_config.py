import os
import pathlib
import shutil
import sys
from typing import Annotated, Any, Optional

from dotenv import load_dotenv
from pydantic.functional_validators import BeforeValidator
from pydantic.v1 import BaseSettings, Field, root_validator

load_dotenv()

MICROSERVICE_NAME = "auth-service"


def options_decoder(v):
    if isinstance(v, str):
        return v.split(",")
    return v


OptionsType = Annotated[Any, BeforeValidator(options_decoder)]


class _Service(BaseSettings):
    MODULE_NAME: str = Field(default="Auth-Service-v2")
    HOST: str = Field(default="0.0.0.0", env="service_host")
    PORT: int = Field(default=7120, env="service_port")
    WORKERS: int = Field(default=1)
    ENABLE_CORS: bool = True
    CORS_URLS: str = Field(default="*.travel.com")
    CORS_ALLOW_CREDENTIALS: bool = True
    CORS_ALLOW_METHODS: list[str] = ["GET", "POST", "DELETE", "PUT"]
    CORS_ALLOW_HEADERS: list[str] = ["*"]
    SECURE_COOKIE: bool = Field(default=False)
    SECURE_ACCESS: bool = Field(default=False)
    LOG_ENABLE_TRACEBACK: bool = Field(default=True)
    PROTECTED_HOSTS: OptionsType = ["*.ilens.io", "*.unifytwin.com"]
    VERIFY_SIGNATURE: bool = Field(default=False)
    SW_DOCS_URL: Optional[str] = ""
    SW_OPENAPI_URL: Optional[str] = ""
    LOG_LEVEL: str = "DEBUG"
    ENABLE_FILE_LOG: Optional[Any] = False
    ENABLE_CONSOLE_LOG: Optional[Any] = True

    @root_validator(allow_reuse=True)
    def validate_values(cls, values):
        values["LOG_LEVEL"] = values["LOG_LEVEL"] or "INFO"
        print(f"Logging Level set to: {values['LOG_LEVEL']}")
        print(f"Logging Level set to: {values['VERIFY_SIGNATURE']}")
        return values


class _Databases(BaseSettings):
    MONGO_URI: Optional[str]
    POSTGRES_URI: Optional[str]
    REDIS_URI: Optional[str]
    REDIS_LOGIN_DB: Optional[int] = 9
    PG_SCHEMA: Optional[str] = "public"
    PG_POOL_SIZE: str = Field(default="20")
    PG_MAX_OVERFLOW: str = Field(default="10")

    @root_validator(allow_reuse=True)
    def validate_values(cls, values):
        if not values["MONGO_URI"]:
            print("Error, environment variable MONGO_URI not set")
            sys.exit(1)
        if not values["POSTGRES_URI"]:
            print("Environment variable POSTGRES_URI not set, proceeding without Postgres Support")
            sys.exit(1)
        return values


class _StoragePaths(BaseSettings):
    MODULE_NAME: str = "auth-service-v2"
    BASE_PATH: str
    REPORT_PATH: str = Field(None)

    @root_validator(allow_reuse=True)
    def assign_values(cls, values):
        values["BASE_PATH"] = os.path.join("data", values.get("MODULE_NAME"))
        if not values["BASE_PATH"]:
            print("Error, environment variable BASE_PATH not set")
            sys.exit(1)
        values["REPORT_PATH"] = os.path.join(values.get("BASE_PATH"), "reports")
        return values


class _PathToStorage(BaseSettings):
    BASE_PATH: pathlib.Path = Field(None, env="BASE_PATH")
    MOUNT_DIR: pathlib.Path = Field(default="auth-service", env="MOUNT_DIR")

    @root_validator(allow_reuse=True)
    def assign_values(cls, values):
        values["LOGS_MODULE_PATH"] = os.path.join(values.get("BASE_PATH"), "logs", values.get("MOUNT_DIR"))
        values["MODULE_PATH"] = os.path.join(values.get("BASE_PATH"), values.get("MOUNT_DIR"))
        return values

    @root_validator(allow_reuse=True)
    def validate_values(cls, values):
        if not values["BASE_PATH"]:
            print("Error, environment variable BASE_PATH not set")
            sys.exit(1)
        if not values["MOUNT_DIR"]:
            print("Error, environment variable MOUNT_DIR not set")
            sys.exit(1)
        return values


class _Security(BaseSettings):
    ENABLE_CORS: bool = Field(default=True) in ["True", "true", True]
    CORS_URLS: str
    PROTECTED_HOSTS: OptionsType
    SECURE_ACCESS: bool = Field(default=True) in ["True", "true", True]
    SECURE_COOKIE: bool = Field(default=True) in ["True", "true", True]
    VERIFY_SIGNATURE: bool = Field(default=False) in ["True", "true", True]
    PASSWORD_DECRYPTION_KEY: str = "QVY1bWdMQ0Zxc"
    DISABLE_ENC: bool | str = Field(default=True) in ["True", "true", True]
    VALIDATE_LIMIT: bool | str = Field(default=False) in ["True", "true", True]
    ENCRYPTION_CONSTANTS_FILE_PATH: str = "conf/mongo_encryption_constants.json"
    USER_ENCRYPTION: bool = os.environ.get("USER_ENCRYPTION", default=True) in [True, "true", "True"]
    COOKIE_MAX_AGE_IN_MINS: int = Field(default=60)
    FIXED_DELAY: int = Field(default=5)
    VARIABLE_DELAY: int = Field(default=30)
    MAX_LOGIN_ATTEMPTS: int = Field(default=10)
    DELAY_LOGIN_ATTEMPTS: int = Field(default=3)
    REFRESH_TOKEN_DURATION: int = Field(default=168)
    LOCK_OUT_TIME_MINS: int = Field(default=2880)
    ENABLE_SECURITY: bool = Field(default=False) in ["True", "true", True]
    HTTP_FLAG: bool = Field(default=True) in ["True", "true", True]
    COOKIE_TIMEOUT: int = Field(default=86400)
    ADD_SESSION_ID: bool = Field(default=True)


class _KeyPath(BaseSettings):
    KEYS_PATH: Optional[pathlib.Path] = Field("data/keys")
    PUBLIC: Optional[pathlib.Path]
    PRIVATE: Optional[pathlib.Path]

    @root_validator(allow_reuse=True)
    def assign_values(cls, values):
        if not os.path.isfile(os.path.join(values.get("KEYS_PATH"), "public")) or not os.path.isfile(
            os.path.join(values.get("KEYS_PATH"), "private")
        ):
            if not os.path.exists(values.get("KEYS_PATH")):
                os.makedirs(values.get("KEYS_PATH"))
            shutil.copy(os.path.join("assets", "keys", "public"), os.path.join(values.get("KEYS_PATH"), "public"))
            shutil.copy(os.path.join("assets", "keys", "private"), os.path.join(values.get("KEYS_PATH"), "private"))
        values["PUBLIC"] = os.path.join(values.get("KEYS_PATH"), "public")
        values["PRIVATE"] = os.path.join(values.get("KEYS_PATH"), "private")
        return values


class _MQTTConf(BaseSettings):
    MQTT_HOST: str
    MQTT_PORT: int
    MQTT_USERNAME: str
    MQTT_PASSWORD: str
    PUBLISH_BASE_TOPIC: str = "ilens/notifications"


Service = _Service()
DBConf = _Databases()
StoragePaths = _StoragePaths()
PathToStorage = _PathToStorage()
KeyPath = _KeyPath()
Security = _Security()
MQTTConf = _MQTTConf()

__all__ = [
    "MICROSERVICE_NAME",
    "Service",
    "DBConf",
    "StoragePaths",
    "PathToStorage",
    "Security",
    "KeyPath",
    "MQTTConf",
]
