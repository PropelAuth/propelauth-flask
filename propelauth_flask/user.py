from enum import Enum

from propelauth_flask.errors import _UnauthorizedException


class User:
    def __init__(self, user_id, org_id_to_org_member_info):
        self.user_id = user_id
        self.org_id_to_org_member_info = org_id_to_org_member_info

    def exists(self):
        return True

    def __eq__(self, other):
        if isinstance(other, User):
            return self.user_id == other.user_id and self.org_id_to_org_member_info == other.org_id_to_org_member_info
        return False


# If a user is not logged in, optional_user will still allow the request to continue
# Ideally, current_user would just be none. However, since current_user is a proxy,
#   the check `current_user is None` actually returns false.
# You can do current_user._get_current_object() is None but that feels clunky.
# Instead, we'll make it an explicit type add a function `exists()` to distinguish the cases.
class LoggedOutUser:
    def exists(self):
        return False


class OrgMemberInfo:
    def __init__(self, org_id, org_name, user_role):
        self.org_id = org_id
        self.org_name = org_name
        self.user_role = user_role

    def __eq__(self, other):
        if isinstance(other, OrgMemberInfo):
            return self.org_id == other.org_id and \
                   self.org_name == other.org_name and \
                   self.user_role == other.user_role
        return False


def _to_org_member_info(org_id_to_org_member_info_json):
    if org_id_to_org_member_info_json is None:
        return None

    org_id_to_org_member_info = {}
    for org_id, org_member_info_json in org_id_to_org_member_info_json.items():
        user_role = _to_user_role(org_member_info_json["user_role"])
        if user_role is not None:
            org_id_to_org_member_info[org_id] = OrgMemberInfo(
                org_id=org_member_info_json["org_id"],
                org_name=org_member_info_json["org_name"],
                user_role=user_role
            )
    return org_id_to_org_member_info


def _to_user_role(user_role):
    if user_role == "Owner":
        return UserRole.Owner
    elif user_role == "Admin":
        return UserRole.Admin
    elif user_role == "Member":
        return UserRole.Member
    else:
        return None


def _to_user(decoded_token):
    user_id = decoded_token.get("user_id")
    if user_id is None:
        raise _UnauthorizedException("Invalid payload in token")

    org_id_to_org_member_info = _to_org_member_info(decoded_token.get("org_id_to_org_member_info"))
    return User(user_id, org_id_to_org_member_info)


class _OrderedEnum(Enum):
    def __ge__(self, other):
        if self.__class__ is other.__class__:
            return self.value >= other.value
        return NotImplemented

    def __gt__(self, other):
        if self.__class__ is other.__class__:
            return self.value > other.value
        return NotImplemented

    def __le__(self, other):
        if self.__class__ is other.__class__:
            return self.value <= other.value
        return NotImplemented

    def __lt__(self, other):
        if self.__class__ is other.__class__:
            return self.value < other.value
        return NotImplemented


class UserRole(_OrderedEnum):
    Member = 0,
    Admin = 1,
    Owner = 2,
