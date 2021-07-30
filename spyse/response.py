from dataclasses import dataclass
from typing import List, Optional
from dataclasses_json import dataclass_json


@dataclass_json
@dataclass
class FieldError:
    code: Optional[str] = None
    location: Optional[str] = None
    message: Optional[str] = None


@dataclass_json
@dataclass
class Error:
    status: Optional[int] = None
    code: Optional[str] = None
    message: Optional[str] = None
    errors: Optional[List[FieldError]] = None


@dataclass_json
@dataclass
class Data:
    limit: Optional[int] = None
    offset: Optional[int] = None
    search_id: Optional[str] = None
    total_items: Optional[int] = None
    items: Optional[List[object]] = None


class SpyseError(Exception):
    def __init__(self, message):
        self.message = message


class BadRequestError(SpyseError):
    pass


class ParamsValidationError(SpyseError):
    pass


class RequestLimitReachedError(SpyseError):
    pass


class DownloadsLimitReachedError(SpyseError):
    pass


class SearchParamsLimitReachedError(SpyseError):
    pass


class UnauthorizedError(SpyseError):
    pass


class ForbiddenError(SpyseError):
    pass


class InternalServerError(SpyseError):
    pass


class UnknownError(SpyseError):
    pass


@dataclass_json
@dataclass
class Response:
    CODE_BAD_REQUEST = 'bad_request'
    CODE_VALIDATION_ERROR = 'validation_error'
    CODE_REQUESTS_LIMIT_REACHED = 'requests_limit_reached'
    CODE_DOWNLOADS_LIMIT_REACHED = 'downloads_limit_reached'
    CODE_SEARCH_PARAMS_LIMIT_REACHED = 'search_params_limit_reached'
    CODE_UNAUTHORIZED = 'unauthorized'
    CODE_FORBIDDEN = 'forbidden'
    CODE_INTERNAL_SERVER_ERROR = 'internal_server_error'

    data: Optional[Data] = None
    error: Optional[Error] = None

    def check_errors(self) -> None:
        """Will rise a specific error if it is indicated in the API response"""
        if not self.error:
            return

        m = self.error.errors[0].message if self.error.errors and len(self.error.errors) > 0 else self.error.message
        if self.error.code == self.CODE_BAD_REQUEST:
            raise BadRequestError(m)
        elif self.error.code == self.CODE_VALIDATION_ERROR:
            raise ParamsValidationError(m)
        elif self.error.code == self.CODE_REQUESTS_LIMIT_REACHED:
            raise RequestLimitReachedError(m)
        elif self.error.code == self.CODE_DOWNLOADS_LIMIT_REACHED:
            raise DownloadsLimitReachedError(m)
        elif self.error.code == self.CODE_SEARCH_PARAMS_LIMIT_REACHED:
            raise SearchParamsLimitReachedError(m)
        elif self.error.code == self.CODE_UNAUTHORIZED:
            raise UnauthorizedError(m)
        elif self.error.code == self.CODE_FORBIDDEN:
            raise ForbiddenError(m)
        elif self.error.code == self.CODE_INTERNAL_SERVER_ERROR:
            raise InternalServerError(m)
        else:
            raise UnknownError(m)
