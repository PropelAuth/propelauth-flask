<p align="center">
  <a href="https://www.propelauth.com?ref=github" target="_blank" align="center">
    <img src="https://www.propelauth.com/imgs/lockup.svg" width="200">
  </a>
</p>

# PropelAuth Flask SDK

A Flask library for managing authentication, backed by [PropelAuth](https://www.propelauth.com/?utm_campaign=github-flask).

[PropelAuth](https://www.propelauth.com?ref=github) makes it easy to add authentication and authorization to your B2B/multi-tenant application.

Your frontend gets a beautiful, safe, and customizable login screen. Your backend gets easy authorization with just a few lines of code. You get an easy-to-use dashboard to config and manage everything.

## Documentation

- Full reference this library is [here](https://docs.propelauth.com/reference/backend-apis/flask)
- Getting started guides for PropelAuth are [here](https://docs.propelauth.com/)

## Installation

```bash
pip install propelauth_flask
```

## Initialize

`init_auth` performs a one-time initialization of the library. 
This verifies your `api_key` and fetches the metadata needed to verify access tokens in [require_user](#require-user) and [optional_user](#optional-user).


```py
from propelauth_flask import init_auth

auth = init_auth("YOUR_AUTH_URL", "YOUR_API_KEY")
```

# Protect API Routes

Protecting an API route is as simple as adding a decorator to the route.

None of the decorators make a external request to PropelAuth. 
    They all are verified locally using the [access token](https://docs.propelauth.com/guides-and-examples/guides/access-tokens) provided in the request, making it very fast.

## require_user

A decorator that will verify the request was made by a valid user. 
If a valid [access token](https://docs.propelauth.com/guides-and-examples/guides/access-tokens) is provided, it will return a [User](https://docs.propelauth.com/reference/backend-apis/flask#user) Class. 
If not, the request is rejected with a 401 status code.

```py
from flask import Flask
from propelauth_flask import init_auth, current_user

app = Flask(__name__)
auth = init_auth("YOUR_AUTH_URL", "YOUR_API_KEY")

@app.route("/api/whoami")
@auth.require_user
def who_am_i():
    """This route is protected, current_user is always set"""
    return {"user_id": current_user.user_id}
```

## optional_user

Similar to [require_user](#require-user), except if an access token is missing or invalid, the request is allowed to continue, but `current_user.exists()` will be `False`.

```py
from flask import Flask
from propelauth_flask import init_auth, current_user

app = Flask(__name__)
auth = init_auth("YOUR_AUTH_URL", "YOUR_API_KEY")

@app.route("/api/whoami_optional")
@auth.optional_user
def who_am_i_optional():
    if current_user.exists():
        return {"user_id": current_user.user_id}
    return {}
```

---

## current_user

A per-request value that contains user information for the user making the request. It's set by one of [require_user](#require-user) or [optional_user](#optional-user).

It has all the fields on the [User](https://docs.propelauth.com/reference/backend-apis/flask#user) class, as well as an `exists()` method that returns `True` if the user exists.
The only time `exists()` will return `False` is if you are using [optional_user](#optional-user) and no valid access token was provided.

If you want to take advantage of type support, you can import the `User` class to define a new user variable.

```py
from flask import Flask
from propelauth_flask import init_auth, current_user, User

app = Flask(__name__)
auth = init_auth("YOUR_AUTH_URL", "YOUR_API_KEY")

@app.route("/api/whoami")
@auth.require_user
def who_am_i():
    user: User = current_user.user
    return {"user_id": user.user_id}
```

## Authorization / Organizations

You can also verify which organizations the user is in, and which roles and permissions they have in each organization all through the [User Class](https://docs.propelauth.com/reference/backend-apis/flask#user).

### Check Org Membership

Verify that the request was made by a valid user **and** that the user is a member of the specified organization. This can be done using the [User](https://docs.propelauth.com/reference/backend-apis/flask#user) class.

```py
@app.route("/api/org/<org_id>", methods=['GET'])
@auth.require_user
def org_membership(org_id):
    org = current_user.get_org(org_id)
    if org == None:
        # Return a 403 error, e.g.: return "Forbidden", 403
    return f"You are in org {org.org_name}"
```

### Check Org Membership and Role

Similar to checking org membership, but will also verify that the user has a specific Role in the organization. This can be done using either the [User](https://docs.propelauth.com/reference/backend-apis/flask#user) or [OrgMemberInfo](https://docs.propelauth.com/reference/backend-apis/flask#org-member-info) classes.

A user has a Role within an organization. By default, the available roles are Owner, Admin, or Member, but these can be configured. These roles are also hierarchical, so Owner > Admin > Member.

```py
## Assuming a Role structure of Owner => Admin => Member

@app.route("/api/org/<org_id>", methods=['GET'])
@auth.require_user
def org_owner(org_id):
    org = current_user.get_org(org_id)
    if (org == None) or (org.user_is_role("Owner") == False):
        # return 403 error
    return f"You are in org {org.org_name}"
```

### Check Org Membership and Permission

Similar to checking org membership, but will also verify that the user has the specified permission in the organization. This can be done using either the [User](https://docs.propelauth.com/reference/backend-apis/flask#user) or [OrgMemberInfo](https://docs.propelauth.com/reference/backend-apis/flask#org-member-info) classes.

Permissions are arbitrary strings associated with a role. For example, `can_view_billing`, `ProductA::CanCreate`, and `ReadOnly` are all valid permissions. 
You can create these permissions in the PropelAuth dashboard.

```py
@app.route("/api/org/<org_id>", methods=['GET'])
@auth.require_user
def org_billing(org_id):
    org = current_user.get_org(org_id)
    if (org == None) or (org.user_has_permission("can_view_billing") == False):
        # return 403 error
    return f"You can view billing information for org {org.org_name}"
```

## Calling Backend APIs

You can also use the library to call the PropelAuth APIs directly, allowing you to fetch users, create orgs, and a lot more. 
See the [API Reference](https://docs.propelauth.com/reference) for more information.

```py
from propelauth_flask import init_auth

auth = init_auth("YOUR_AUTH_URL", "YOUR_API_KEY")

magic_link = auth.create_magic_link(email="test@example.com")
```

## Questions?

Feel free to reach out at support@propelauth.com
