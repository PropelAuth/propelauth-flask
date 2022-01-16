from propelauth_py.user import User, UserRole


class LoggedInUser:
    def __init__(self, user: User):
        self.user_id = user.user_id
        self.org_id_to_org_member_info = user.org_id_to_org_member_info

    def exists(self):
        return True

    def __eq__(self, other):
        if isinstance(other, LoggedInUser):
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
