import jwt
from jwt.exceptions import (
    ExpiredSignatureError,
    InvalidSignatureError,
    MissingRequiredClaimError,
)

from scripts.constants.env_config import KeyPath
from scripts.constants import Secrets
from scripts.errors import AuthenticationError, ErrorMessages
from scripts.logging.logging import logger


class JWT:
    def __init__(self):
        self.max_login_age = Secrets.LOCK_OUT_TIME_MINS
        self.issuer = Secrets.issuer
        self.alg = Secrets.alg
        self.public = KeyPath.PUBLIC
        self.private = KeyPath.PRIVATE

    def encode(self, payload):
        try:
            logger.debug("Inside encode")
            with open(self.private) as f:
                key = f.read()
            return jwt.encode(payload, key, algorithm=self.alg)
        except Exception as e:
            logger.debug(f"Exception in encode: {str(e)}")
            raise
        finally:
            f.close()

    def validate(self, token):
        try:
            logger.debug("Inside validate")
            with open(self.public) as f:
                key = f.read()
            payload = jwt.decode(
                token,
                key,
                algorithms=self.alg,
                leeway=Secrets.leeway_in_mins,
                options={"require": ["exp", "iss"]},
            )
            return payload
        except InvalidSignatureError:
            raise AuthenticationError(ErrorMessages.ERROR003)
        except ExpiredSignatureError:
            raise AuthenticationError(ErrorMessages.ERROR002)
        except MissingRequiredClaimError:
            raise AuthenticationError(ErrorMessages.ERROR002)
        except Exception as e:
            logger.debug(f"Exception in validate: {str(e)}")
            raise
        finally:
            f.close()
