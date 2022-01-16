from collections import namedtuple

from flask import _request_ctx_stack
from propelauth_py import TokenVerificationMetadata, init_base_auth
from werkzeug.local import LocalProxy

from propelauth_flask.auth_decorator import _get_user_credential_decorator, _get_require_org_decorator

'''Returns the current user. Must be used with one of require_user, optional_user, or require_org_member'''
current_user = LocalProxy(lambda: getattr(_request_ctx_stack.top, "propelauth_current_user", None))

'''Returns the current org. Must be used with require_org_member'''
current_org = LocalProxy(lambda: getattr(_request_ctx_stack.top, "propelauth_current_org", None))

Auth = namedtuple("Auth", [
    "require_user", "optional_user", "require_org_member",
    "fetch_user_metadata_by_user_id", "fetch_user_metadata_by_email", "fetch_user_metadata_by_username",
    "fetch_batch_user_metadata_by_user_ids",
    "fetch_batch_user_metadata_by_emails",
    "fetch_batch_user_metadata_by_usernames"
])


def init_auth(auth_url: str, api_key: str, token_verification_metadata: TokenVerificationMetadata = None,
              debug_mode=False):
    """Fetches metadata required to validate access tokens and returns auth decorators and utilities"""

    auth = init_base_auth(auth_url, api_key, token_verification_metadata)
    return Auth(
        require_user=_get_user_credential_decorator(auth.validate_access_token_and_get_user, True, debug_mode),
        optional_user=_get_user_credential_decorator(auth.validate_access_token_and_get_user, False, debug_mode),
        require_org_member=_get_require_org_decorator(auth.validate_access_token_and_get_user_with_org, debug_mode),
        fetch_user_metadata_by_user_id=auth.fetch_user_metadata_by_user_id,
        fetch_user_metadata_by_email=auth.fetch_user_metadata_by_email,
        fetch_user_metadata_by_username=auth.fetch_user_metadata_by_username,
        fetch_batch_user_metadata_by_user_ids=auth.fetch_batch_user_metadata_by_user_ids,
        fetch_batch_user_metadata_by_emails=auth.fetch_batch_user_metadata_by_emails,
        fetch_batch_user_metadata_by_usernames=auth.fetch_batch_user_metadata_by_usernames,
    )
