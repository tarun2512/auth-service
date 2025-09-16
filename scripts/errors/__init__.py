class ILensErrors(Exception):
    def __init__(self, msg):
        Exception.__init__(self, msg)

    """
    Base Error Class
    """


class ILensErrorsWithoutMessage(Exception):
    """Generic iLens Error"""


class ErrorMessages:
    ERROR001 = "Authentication Failed. Please verify token"
    ERROR002 = "Signature Expired"
    ERROR003 = "Signature Not Valid"
    ERROR004 = "User Record Not Found"
    WORKSPACE_CATALOG_URL_ERROR = "Invalid Catalog Url"


class JobCreationError(Exception):
    """
    Raised when a Job Creation throws an exception.

    Job Creation happens by adding a record to Mongo.
    """


class UnknownError(Exception):
    pass


class DuplicateSpaceNameError(Exception):
    pass


class KairosDBError(Exception):
    pass


class UnauthorizedError(Exception):
    pass


class ImageValidation(Exception):
    pass


class ILensError(Exception):
    pass


class NameExists(Exception):
    pass


class InputRequestError(ILensError):
    pass


class IllegalTimeSelectionError(ILensError):
    pass


class DataNotFound(Exception):
    pass


class AuthenticationError(ILensError):
    """
    JWT Authentication Error
    """


class JWTDecodingError(Exception):
    pass


class DuplicateReportNameError(Exception):
    pass


class PathNotExistsException(Exception):
    pass


class ImplementationError(Exception):
    pass


class UserRoleNotFoundException(Exception):
    pass


class CustomError(Exception):
    pass


class IllegalToken(ILensErrors):
    pass


class InvalidPasswordError(ILensErrors):
    pass


class UserNotFound(ILensErrors):
    pass


class TooManyRequestsError(Exception):
    pass


class FixedDelayError(ILensErrors):
    pass


class InvalidAuthorizationToken(Exception):
    pass


class VariableDelayError(ILensErrors):
    pass


class LicenceValidationError(Exception):
    pass


class CustomAppError:
    FAILED_TO_SAVE = "Failed to save app"


class WorkspaceNameExistError(ILensErrorsWithoutMessage):
    pass


class GlobalCatalogError(Exception):
    """Generic GlobalcatalogErrors Error"""

    def __init__(self, msg):
        Exception.__init__(self, msg)

    """
        Base Error Class
    """
