from ckan import plugins
import ckan.model as model
from ckan.plugins import toolkit

from ckanext.saml2auth.interfaces import ISaml2Auth

import logging


log = logging.getLogger(__name__)

CKAN_ADMIN_ROLE = "ckan-admin-9846AitQ"

FALLBACK_MEMBER_ROLE = "member"

ordered_role_mappings = [
    ["Org-admin", "admin"],
    ["Org-Editor", "editor"],
    ["Org-member", "member"],
]
"""
A mapping of the expected SAML role attribute to the organization role.

This mapping is ordered by priority. For example, users with both Org-admin and Org-member roles
should be assigned the admin role because Org-admin appears first in the mapping.
"""


class SsoPlugin(plugins.SingletonPlugin):
    plugins.implements(plugins.IConfigurer)
    plugins.implements(ISaml2Auth, inherit=True)

    def update_config(self, config_):
        toolkit.add_template_directory(config_, 'templates')

    def after_saml2_login(self, resp, saml_attributes):
        roles = saml_attributes.get("Role", [])
        is_ckan_admin = has_role(roles, CKAN_ADMIN_ROLE)
        user_org_role = next(
            (mapping[1] for mapping in ordered_role_mappings if has_role(roles, mapping[0])),
            FALLBACK_MEMBER_ROLE
        )

        username = str(toolkit.g.userobj.name)
        user_id = str(toolkit.g.userobj.id)
        user = model.User.by_name(username)

        if is_ckan_admin: # add sysadmin privileges
            user.sysadmin = True
            model.Session.add(user)
            model.Session.commit()
            return resp
        else: # remove sysadmin privileges
            user.sysadmin = False
            model.Session.add(user)
            model.Session.commit()
                
            # get users organisation from saml attributes
            try:
                expected_org_title = saml_attributes["member"][0] # use the first organization in the list only
                expected_org_name = expected_org_title.replace(' ', '-').lower()
            except (KeyError, IndexError):
                log.error("%s doesn't have a organisation", username)
                return resp
            
            # Remove from all orgs other than the one they are meant to be in
            current_orgs = toolkit.get_action("organization_list_for_user")({'ignore_auth': True}, {})
            IsInOrg = False
            for org in current_orgs:
                if org["name"] == expected_org_name: #if user is already in correct org
                    IsInOrg = True
                else:
                    try:
                        toolkit.get_action("organization_member_delete")({'ignore_auth': True}, {"id": org["name"], "username": user_id})
                    except:
                        log.error("Cannot delete from: %s", org["name"])

            if IsInOrg: #If user is already in the org no need to do processing below
                return resp
            
            # Get all organisations
            try:
                organization = toolkit.get_action("organization_show")({'ignore_auth': True}, {"id": expected_org_name})
            except toolkit.ObjectNotFound:
                organization = None

            # Check if their organisation exist. If it does, add them to it at assigned level
            try:
                if organization:
                    log.info("adding user %s to organization %s", username, organization['name'])
                    data = {"id" : organization["id"] , "username" : user_id, "role" : user_org_role}
                    toolkit.get_action("organization_member_create")({'ignore_auth': True}, data)
                else:
                    log.info("creating organization %s with user %s", expected_org_name, username)
                    org_users = [{"name" : user_id, "capacity": user_org_role}]
                    data = {"name": expected_org_name, "title": expected_org_title, "users": org_users}
                    toolkit.get_action("organization_create")({'ignore_auth': True}, data)
            except:
                log.exception("unable to create user %s organization membership for %s", username, expected_org_name)

            return resp


def has_role(roles, role):
    return any(r == role for r in roles)
