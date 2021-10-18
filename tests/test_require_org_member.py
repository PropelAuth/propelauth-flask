from datetime import timedelta
from uuid import uuid4

from propelauth_flask import current_user, current_org
from propelauth_flask.user import UserRole
from tests.auth_helpers import create_access_token, orgs_to_org_id_map, random_org, random_user_id
from tests.conftest import HTTP_BASE_AUTH_URL

ROUTE_NAME = "/require_org_member_route"
ROUTE_NAME_WITH_ORG_ID = "/require_org_member_route/<org_id>"


def test_require_org_member_without_auth(app, auth, client, rsa_keys):
    create_route_expecting_user_and_org(app, auth, None, None, None)
    org_id = str(uuid4())

    response = client.get(route_for(org_id))
    assert response.status_code == 401


def test_require_org_member_with_auth_but_no_org_membership(app, auth, client, rsa_keys):
    create_route_expecting_user_and_org(app, auth, None, None, None)
    org_id = str(uuid4())

    user_id = random_user_id()
    access_token = create_access_token({"user_id": user_id}, rsa_keys.private_pem)
    response = client.get(route_for(org_id), headers={"Authorization": "Bearer " + access_token})
    assert response.status_code == 401


def test_require_org_member_with_auth_and_org_member(app, auth, client, rsa_keys):
    user_id = random_user_id()
    org = random_org("Owner")
    org_id_to_org_member_info = orgs_to_org_id_map([org])

    create_route_expecting_user_and_org(app, auth, user_id, org, UserRole.Owner)

    access_token = create_access_token({
        "user_id": user_id,
        "org_id_to_org_member_info": org_id_to_org_member_info
    }, rsa_keys.private_pem)

    response = client.get(route_for(org["org_id"]), headers={"Authorization": "Bearer " + access_token})
    assert response.status_code == 200
    assert response.data.decode("utf-8") == "ok"


def test_require_org_member_with_auth_but_wrong_org_id(app, auth, client, rsa_keys):
    user_id = random_user_id()
    org = random_org("Owner")
    org_id_to_org_member_info = orgs_to_org_id_map([org])
    wrong_org_id = str(uuid4())

    create_route_expecting_user_and_org(app, auth, user_id, org, UserRole.Owner)

    access_token = create_access_token({
        "user_id": user_id,
        "org_id_to_org_member_info": org_id_to_org_member_info
    }, rsa_keys.private_pem)

    # Pass wrong org_id as a path parameter
    response = client.get(route_for(wrong_org_id), headers={"Authorization": "Bearer " + access_token})
    assert response.status_code == 403


def test_require_org_member_with_auth_but_no_permission(app, auth, client, rsa_keys):
    user_id = random_user_id()
    org = random_org("Member")
    org_id_to_org_member_info = orgs_to_org_id_map([org])

    @app.route(ROUTE_NAME_WITH_ORG_ID)
    @auth.require_org_member(minimum_required_role=UserRole.Admin)
    def route(org_id):
        return "ok"

    access_token = create_access_token({
        "user_id": user_id,
        "org_id_to_org_member_info": org_id_to_org_member_info
    }, rsa_keys.private_pem)

    response = client.get(route_for(org["org_id"]), headers={"Authorization": "Bearer " + access_token})
    assert response.status_code == 403


def test_require_org_member_with_auth_with_permission(app, auth, client, rsa_keys):
    user_id = random_user_id()
    org = random_org("Admin")
    org_id_to_org_member_info = orgs_to_org_id_map([org])

    @app.route(ROUTE_NAME_WITH_ORG_ID)
    @auth.require_org_member(minimum_required_role=UserRole.Admin)
    def route(org_id):
        assert current_user.user_id == user_id
        assert current_org.org_id == org["org_id"]
        assert current_org.org_name == org["org_name"]
        assert current_org.user_role == UserRole.Admin
        return "ok"

    access_token = create_access_token({
        "user_id": user_id,
        "org_id_to_org_member_info": org_id_to_org_member_info
    }, rsa_keys.private_pem)

    response = client.get(route_for(org["org_id"]), headers={"Authorization": "Bearer " + access_token})
    assert response.status_code == 200
    assert response.data.decode("utf-8") == "ok"


def test_require_org_member_with_bad_header(app, auth, client, rsa_keys):
    create_route_expecting_user_and_org(app, auth, None, None, None)

    user_id = random_user_id()
    org = random_org("Admin")
    org_id_to_org_member_info = orgs_to_org_id_map([org])

    access_token = create_access_token({
        "user_id": user_id,
        "org_id_to_org_member_info": org_id_to_org_member_info
    }, rsa_keys.private_pem)

    response = client.get(route_for(org["org_id"]), headers={"Authorization": "token " + access_token})
    assert response.status_code == 401


def test_require_org_member_with_wrong_token(app, auth, client, rsa_keys):
    create_route_expecting_user_and_org(app, auth, None, None, None)
    org_id = str(uuid4())

    response = client.get(route_for(org_id), headers={"Authorization": "Bearer whatisthis"})
    assert response.status_code == 401


def test_require_org_member_with_expired_token(app, auth, client, rsa_keys):
    user_id = random_user_id()
    org = random_org("Owner")
    org_id_to_org_member_info = orgs_to_org_id_map([org])

    create_route_expecting_user_and_org(app, auth, user_id, org, UserRole.Owner)

    access_token = create_access_token({
        "user_id": user_id,
        "org_id_to_org_member_info": org_id_to_org_member_info
    }, rsa_keys.private_pem, expires_in=timedelta(minutes=-1))

    response = client.get(route_for(org["org_id"]), headers={"Authorization": "Bearer " + access_token})
    assert response.status_code == 401


def test_require_user_with_bad_issuer(app, auth, client, rsa_keys):
    user_id = random_user_id()
    org = random_org("Owner")
    org_id_to_org_member_info = orgs_to_org_id_map([org])

    create_route_expecting_user_and_org(app, auth, user_id, org, UserRole.Owner)

    access_token = create_access_token({
        "user_id": user_id,
        "org_id_to_org_member_info": org_id_to_org_member_info
    }, rsa_keys.private_pem, issuer=HTTP_BASE_AUTH_URL)

    response = client.get(route_for(org["org_id"]), headers={"Authorization": "Bearer " + access_token})
    assert response.status_code == 401


def create_route_expecting_user_and_org(app, auth, user_id, org, user_role):
    @app.route(ROUTE_NAME_WITH_ORG_ID)
    @auth.require_org_member()
    def route(org_id):
        assert current_user.user_id == user_id
        assert current_org.org_id == org["org_id"]
        assert current_org.org_name == org["org_name"]
        assert current_org.user_role == user_role
        return "ok"


def route_for(org_id):
    return ROUTE_NAME + "/" + org_id
