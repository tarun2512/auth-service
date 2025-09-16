class UserAccessExceptions:
    UAE = "User doesn't have the access"


class UserExceptions:
    UID_UN_NOT_EMPTY = "Both user_id and user_name cannot be empty"
    FAILED_TO_SAVE = "Failed to save the user details"
    USER_INACTIVE = "User Inactive, please contact administrator"
    EMAIL_SEND_FAIL = "Failed to reset password mail, please contact administrator"
    INCORRECT_USERID = "Failed. Incorrect user id or user id doesn’t exist. Please try again."
    USER_NOT_EXIST = "User does not Exists"
    KEYCLOAK_CONNECTION_ERROR = "Failed to connect to keycloak"
    KEYCLOAK_USER_CREATION_ERROR = "Failed to create user in keycloak"


class DefaultExceptionsCode:
    DE001 = "Failed to login! Unauthorised!"
    DE002 = "Failed to login! Invalid authentication code"
    DE003 = "Your password has expired. Please click 'Forgot Password' to reset it and continue using your account."
    DEIP = "Failed to login! Unauthorised!"
    DEIL = "Failed to login! Please contact administrator"
    DE004 = "Too many failed attempts! Please try again after 10 seconds"
    DE006 = "Please wait a moment before attempting to login again."


class EmailMessage:
    EME001 = "Secret key to reset the password has been sent to registered email address."


class CaptchaError:
    VALIDATION_FAILED = "Captcha Validation failed"
