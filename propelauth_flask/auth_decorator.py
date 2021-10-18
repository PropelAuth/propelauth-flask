import functools

from flask import _request_ctx_stack, request, abort, Response

from propelauth_flask.errors import _UnauthorizedException, _UnexpectedException, _ForbiddenException
from propelauth_flask.jwt import _validate_access_token_and_get_user
from propelauth_flask.user import UserRole, LoggedOutUser


def _get_user_credential_decorator(token_verification_metadata, require_user, debug_mode):
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            try:
                access_token = _extract_token_from_authorization_header()
                user = _validate_access_token_and_get_user(access_token, token_verification_metadata)

                _request_ctx_stack.top.propelauth_current_user = user

            except _UnauthorizedException as e:
                _request_ctx_stack.top.propelauth_current_user = LoggedOutUser()
                _return_401_if_user_required(e, require_user, debug_mode)

            return func(*args, **kwargs)

        return wrapper

    return decorator


def _get_require_org_decorator(token_verification_metadata, debug_mode):
    def decorator_that_takes_arguments(req_to_org_id=_default_req_to_org_id, minimum_required_role=None):
        def decorator(func):
            @functools.wraps(func)
            def wrapper(*args, **kwargs):
                try:
                    access_token = _extract_token_from_authorization_header()
                    user = _validate_access_token_and_get_user(access_token, token_verification_metadata)
                    org = _validate_org_access_and_get_org(user, req_to_org_id, minimum_required_role)

                    _request_ctx_stack.top.propelauth_current_user = user
                    _request_ctx_stack.top.propelauth_current_org = org

                except _UnauthorizedException as e:
                    _return_401_if_user_required(e, True, debug_mode)

                except _UnexpectedException as e:
                    _return_exception(e, 503, debug_mode)

                except _ForbiddenException as e:
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


def _extract_token_from_authorization_header():
    authorization_header = request.headers.get("Authorization")
    if authorization_header is None or authorization_header == "":
        raise _UnauthorizedException("No authorization header found")

    auth_header_parts = authorization_header.split(" ")
    if len(auth_header_parts) != 2 or auth_header_parts[0].lower() != "bearer":
        raise _UnauthorizedException("Invalid authorization header. Expected: Bearer {accessToken}")

    return auth_header_parts[1]


def _default_req_to_org_id(req):
    return req.view_args.get('org_id')


def _validate_minimum_required_role(minimum_required_role):
    if minimum_required_role is not None and type(minimum_required_role) is not UserRole:
        raise _UnexpectedException(
            "minimum_required_role must be one of UserRole.Owner, UserRole.Admin, UserRole.Member, or None"
        )


def _validate_org_access_and_get_org(user, req_to_org_id, minimum_required_role):
    _validate_minimum_required_role(minimum_required_role)

    selected_org_id = req_to_org_id(request)
    org_id_to_org_member_info = user.org_id_to_org_member_info

    if org_id_to_org_member_info is None:
        raise _UnauthorizedException("User is not a member of org {}".format(selected_org_id))

    org_member_info = org_id_to_org_member_info.get(selected_org_id)
    if org_member_info is None:
        raise _ForbiddenException("User is not a member of org {}".format(selected_org_id))

    if minimum_required_role is not None and org_member_info.user_role < minimum_required_role:
        raise _ForbiddenException("User's role in org doesn't meet minimum required role")

    return org_member_info
