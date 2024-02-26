import functools

from flask import g, request, abort, Response
from propelauth_py import UnauthorizedException
from propelauth_py.errors import ForbiddenException

from propelauth_flask.user import LoggedOutUser, LoggedInUser


def _get_user_credential_decorator(
    validate_access_token_and_get_user, require_user, debug_mode
):
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            try:
                authorization_header = request.headers.get("Authorization")
                user = validate_access_token_and_get_user(authorization_header)

                g.propelauth_current_user = LoggedInUser(user)

            except UnauthorizedException as e:
                g.propelauth_current_user = LoggedOutUser()
                _return_401_if_user_required(e, require_user, debug_mode)

            return func(*args, **kwargs)

        return wrapper

    return decorator


def _get_require_org_decorator(validate_access_token_and_get_user_with_org, debug_mode):
    def decorator_that_takes_arguments(req_to_org_id=_default_req_to_org_id):
        def decorator(func):
            @functools.wraps(func)
            def wrapper(*args, **kwargs):
                try:
                    authorization_header = request.headers.get("Authorization")
                    required_org_id = req_to_org_id(request)
                    user_and_org = validate_access_token_and_get_user_with_org(
                        authorization_header, required_org_id
                    )

                    g.propelauth_current_user = user_and_org.user
                    g.propelauth_current_org = user_and_org.org_member_info

                except UnauthorizedException as e:
                    _return_401_if_user_required(e, True, debug_mode)

                except ForbiddenException as e:
                    _return_exception(e, 403, debug_mode)

                return func(*args, **kwargs)

            return wrapper

        return decorator

    return decorator_that_takes_arguments


def _require_org_member_with_minimum_role_decorator(
    validate_access_token_and_get_user_with_org_by_minimum_role, debug_mode
):
    def decorator_that_takes_arguments(
        minimum_required_role, req_to_org_id=_default_req_to_org_id
    ):
        def decorator(func):
            @functools.wraps(func)
            def wrapper(*args, **kwargs):
                try:
                    authorization_header = request.headers.get("Authorization")
                    required_org_id = req_to_org_id(request)
                    user_and_org = (
                        validate_access_token_and_get_user_with_org_by_minimum_role(
                            authorization_header, required_org_id, minimum_required_role
                        )
                    )

                    g.propelauth_current_user = user_and_org.user
                    g.propelauth_current_org = user_and_org.org_member_info

                except UnauthorizedException as e:
                    _return_401_if_user_required(e, True, debug_mode)

                except ForbiddenException as e:
                    _return_exception(e, 403, debug_mode)

                return func(*args, **kwargs)

            return wrapper

        return decorator

    return decorator_that_takes_arguments


def _require_org_member_with_exact_role_decorator(
    validate_access_token_and_get_user_with_org_by_exact_role, debug_mode
):
    def decorator_that_takes_arguments(role, req_to_org_id=_default_req_to_org_id):
        def decorator(func):
            @functools.wraps(func)
            def wrapper(*args, **kwargs):
                try:
                    authorization_header = request.headers.get("Authorization")
                    required_org_id = req_to_org_id(request)
                    user_and_org = (
                        validate_access_token_and_get_user_with_org_by_exact_role(
                            authorization_header, required_org_id, role
                        )
                    )

                    g.propelauth_current_user = user_and_org.user
                    g.propelauth_current_org = user_and_org.org_member_info

                except UnauthorizedException as e:
                    _return_401_if_user_required(e, True, debug_mode)

                except ForbiddenException as e:
                    _return_exception(e, 403, debug_mode)

                return func(*args, **kwargs)

            return wrapper

        return decorator

    return decorator_that_takes_arguments


def _require_org_member_with_permission_decorator(
    validate_access_token_and_get_user_with_org_by_permission, debug_mode
):
    def decorator_that_takes_arguments(
        permission, req_to_org_id=_default_req_to_org_id
    ):
        def decorator(func):
            @functools.wraps(func)
            def wrapper(*args, **kwargs):
                try:
                    authorization_header = request.headers.get("Authorization")
                    required_org_id = req_to_org_id(request)
                    user_and_org = (
                        validate_access_token_and_get_user_with_org_by_permission(
                            authorization_header, required_org_id, permission
                        )
                    )

                    g.propelauth_current_user = user_and_org.user
                    g.propelauth_current_org = user_and_org.org_member_info

                except UnauthorizedException as e:
                    _return_401_if_user_required(e, True, debug_mode)

                except ForbiddenException as e:
                    _return_exception(e, 403, debug_mode)

                return func(*args, **kwargs)

            return wrapper

        return decorator

    return decorator_that_takes_arguments


def _require_org_member_with_all_permissions_decorator(
    validate_access_token_and_get_user_with_org_by_all_permissions, debug_mode
):
    def decorator_that_takes_arguments(
        permissions, req_to_org_id=_default_req_to_org_id
    ):
        def decorator(func):
            @functools.wraps(func)
            def wrapper(*args, **kwargs):
                try:
                    authorization_header = request.headers.get("Authorization")
                    required_org_id = req_to_org_id(request)
                    user_and_org = (
                        validate_access_token_and_get_user_with_org_by_all_permissions(
                            authorization_header, required_org_id, permissions
                        )
                    )

                    g.propelauth_current_user = user_and_org.user
                    g.propelauth_current_org = user_and_org.org_member_info

                except UnauthorizedException as e:
                    _return_401_if_user_required(e, True, debug_mode)

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
    return req.view_args.get("org_id")
