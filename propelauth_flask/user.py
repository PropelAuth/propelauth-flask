from typing import List, Optional
from propelauth_py.user import User
from propelauth_py.types.user import OrgIdToOrgMemberInfo
from dataclasses import dataclass

@dataclass
class LoggedInUser:
    user: User

    # Backwards compatibility fields
    user_id: str
    org_id_to_org_member_info: Optional[OrgIdToOrgMemberInfo]
    legacy_user_id: Optional[str] = None

    def __post_init__(self):
        self.user_id = self.user.user_id
        self.org_id_to_org_member_info = self.user.org_id_to_org_member_info
        self.legacy_user_id = self.user.legacy_user_id

    def exists(self) -> bool:
        return True

    def is_impersonated(self) -> bool:
        """Returns true if the user is impersonated"""
        return self.user.is_impersonated()

    def get_active_org(self):
        """Returns the active org member info, if the user has an active org."""
        return self.user.get_active_org()

    def get_active_org_id(self):
        """Returns the active org id, if the user has an active org."""
        return self.user.get_active_org_id()

    def get_org(self, org_id: str):
        """Returns the org member info for the org_id, if the user is in the org."""
        return self.user.get_org(org_id)

    def get_org_by_name(self, org_name: str):
        """Returns the org member info for the org_name, if the user is in the org."""
        return self.user.get_org_by_name(org_name)

    def get_user_property(self, property_name: str):
        """Returns the user property value, if it exists."""
        return self.user.get_user_property(property_name)

    def get_orgs(self):
        """Returns the orgs the user is in."""
        return self.user.get_orgs()

    def is_role_in_org(self, org_id: str, role: str) -> bool:
        """Returns true if the user is the role in the org."""
        return self.user.is_role_in_org(org_id, role)

    def is_at_least_role_in_org(self, org_id: str, role: str) -> bool:
        """Returns true if the user is at least the role in the org."""
        return self.user.is_at_least_role_in_org(org_id, role)

    def has_permission_in_org(self, org_id: str, permission: str) -> bool:
        """Returns true if the user has the permission in the org."""
        return self.user.has_permission_in_org(org_id, permission)

    def has_all_permissions_in_org(self, org_id: str, permissions: List[str]) -> bool:
        """Returns true if the user has all the permissions in the org."""
        return self.user.has_all_permissions_in_org(org_id, permissions)

    def __eq__(self, other) -> bool:
        if isinstance(other, LoggedInUser):
            return self.user == other.user
        return False

# If a user is not logged in, optional_user will still allow the request to continue
# Ideally, current_user would just be none. However, since current_user is a proxy,
#   the check `current_user is None` actually returns false.
# You can do current_user._get_current_object() is None but that feels clunky.
# Instead, we'll make it an explicit type add a function `exists()` to distinguish the cases.
class LoggedOutUser:
    def exists(self):
        return False
