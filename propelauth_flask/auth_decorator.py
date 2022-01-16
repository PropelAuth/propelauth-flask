import functools

from flask import _request_ctx_stack, request, abort, Response
from propelauth_py import UnauthorizedException
from propelauth_py.errors import UnexpectedException, ForbiddenException

from propelauth_flask.user import LoggedOutUser, LoggedInUser


def _get_user_credential_decorator(validate_access_token_and_get_user, require_user, debug_mode):
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            try:
                authorization_header = request.headers.get("Authorization")
                user = validate_access_token_and_get_user(authorization_header)

                _request_ctx_stack.top.propelauth_current_user = LoggedInUser(user)

            except UnauthorizedException as e:
                _request_ctx_stack.top.propelauth_current_user = LoggedOutUser()
                _return_401_if_user_required(e, require_user, debug_mode)

            return func(*args, **kwargs)

        return wrapper

    return decorator


def _get_require_org_decorator(validate_access_token_and_get_user_with_org, debug_mode):
    def decorator_that_takes_arguments(req_to_org_id=_default_req_to_org_id, minimum_required_role=None):
        def decorator(func):
            @functools.wraps(func)
            def wrapper(*args, **kwargs):
                try:
                    authorization_header = request.headers.get("Authorization")
                    required_org_id = req_to_org_id(request)
                    user_and_org = validate_access_token_and_get_user_with_org(authorization_header, required_org_id,
                                                                               minimum_required_role)

                    _request_ctx_stack.top.propelauth_current_user = user_and_org.user
                    _request_ctx_stack.top.propelauth_current_org = user_and_org.org_member_info

                except UnauthorizedException as e:
                    _return_401_if_user_required(e, True, debug_mode)

                except UnexpectedException as e:
                    _return_exception(e, 500, debug_mode)

                except ForbiddenException as e:
                    _return_exception(e, 403, debug_mode)

                return func(*args, **kwargs)

            return wrapper

        return decorator

    return decorator_that_takes_arguments


def _return_401_if_user_required(e, require_user, debug_mode):
    if require_user and debug_mode:
        abort(Response(response=e.message, status=401))
    elif require_user:
        abort(401)


def _return_exception(e, status, debug_mode):
    if debug_mode:
        abort(Response(response=e.message, status=status))
    else:
        abort(status)


def _default_req_to_org_id(req):
    return req.view_args.get('org_id')
