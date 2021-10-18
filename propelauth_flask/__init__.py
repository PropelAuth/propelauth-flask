from collections import namedtuple

from flask import _request_ctx_stack
from werkzeug.local import LocalProxy

from propelauth_flask.api import _fetch_token_verification_metadata, _fetch_user_metadata_by_query, \
    _fetch_batch_user_metadata_by_query
from propelauth_flask.auth_decorator import _get_user_credential_decorator, _get_require_org_decorator
from propelauth_flask.errors import _UnauthorizedException
from propelauth_flask.validation import _validate_url

'''Returns the current user. Must be used with one of require_user, optional_user, or require_org_member'''
current_user = LocalProxy(lambda: getattr(_request_ctx_stack.top, "propelauth_current_user", None))

'''Returns the current org. Must be used with require_org_member'''
current_org = LocalProxy(lambda: getattr(_request_ctx_stack.top, "propelauth_current_org", None))

_Auth = namedtuple("Auth", [
    "require_user", "optional_user", "require_org_member",
    "fetch_user_metadata_by_user_id", "fetch_user_metadata_by_email", "fetch_user_metadata_by_username",
    "fetch_batch_user_metadata_by_user_ids",
    "fetch_batch_user_metadata_by_emails",
    "fetch_batch_user_metadata_by_usernames"
])


def init_auth(auth_url, api_key, debug_mode=False):
    """Fetches metadata required to validate access tokens and returns auth decorators and utilities"""
    auth_url = _validate_url(auth_url)
    token_verification_metadata = _fetch_token_verification_metadata(auth_url, api_key)

    def fetch_user_metadata_by_user_id(user_id):
        return _fetch_user_metadata_by_query(auth_url, api_key, {"user_id": user_id})

    def fetch_user_metadata_by_email(email):
        return _fetch_user_metadata_by_query(auth_url, api_key, {"email": email})

    def fetch_user_metadata_by_username(username):
        return _fetch_user_metadata_by_query(auth_url, api_key, {"username": username})

    def fetch_batch_user_metadata_by_user_ids(user_ids):
        return _fetch_batch_user_metadata_by_query(auth_url, api_key, "user_id", user_ids)

    def fetch_batch_user_metadata_by_emails(emails):
        return _fetch_batch_user_metadata_by_query(auth_url, api_key, "email", emails)

    def fetch_batch_user_metadata_by_usernames(usernames):
        return _fetch_batch_user_metadata_by_query(auth_url, api_key, "username", usernames)

    return _Auth(
        require_user=_get_user_credential_decorator(token_verification_metadata, True, debug_mode),
        optional_user=_get_user_credential_decorator(token_verification_metadata, False, debug_mode),
        require_org_member=_get_require_org_decorator(token_verification_metadata, debug_mode),
        fetch_user_metadata_by_user_id=fetch_user_metadata_by_user_id,
        fetch_user_metadata_by_email=fetch_user_metadata_by_email,
        fetch_user_metadata_by_username=fetch_user_metadata_by_username,
        fetch_batch_user_metadata_by_user_ids=fetch_batch_user_metadata_by_user_ids,
        fetch_batch_user_metadata_by_emails=fetch_batch_user_metadata_by_emails,
        fetch_batch_user_metadata_by_usernames=fetch_batch_user_metadata_by_usernames,
    )
