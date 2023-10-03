from ckan import plugins
import ckan.model as model
import ckan.authz as authz
from ckan.plugins import toolkit

from ckanext.saml2auth.interfaces import ISaml2Auth

from six import text_type
from urllib import request
import logging

log = logging.getLogger(__name__)

class SsoPlugin(plugins.SingletonPlugin):
    plugins.implements(plugins.IConfigurer)
    plugins.implements(ISaml2Auth, inherit=True)

    def update_config(self, config_):
        toolkit.add_template_directory(config_, 'templates')

    def after_saml2_login(self, resp, saml_attributes):

        isCkanAdmin = False
        userOrgRole = "member"
        
        # Try required for if no "role" is in saml attributes
        try:
            for x in saml_attributes["Role"]:
                if (x == "ckan-admin-9846AitQ"):
                    isCkanAdmin = True
                elif (x == "Org-admin"):
                    userOrgRole = "admin"
                elif (x == "Org-Editor"):
                    userOrgRole = "editor"
        except:
            userOrgRole = "member"

        # Admin check
        username = toolkit.g.userobj.name
        user = model.User.by_name(text_type(username))

        if (isCkanAdmin):
            user.sysadmin = True
            model.Session.add(user)
            model.Session.commit()
            return resp # if admin skip, org check
        else:
            user.sysadmin = False
            model.Session.add(user)
            model.Session.commit()

        # Organisation check
        organizations = toolkit.get_action("organization_list")({'ignore_auth': True},{"all_fields": True })

        # Check if their organisation exist
        # If org does exist add them to it at assigned level
        orgChecker = False

        try:
            for x in organizations:
                if (x["title"] == saml_attributes["member"][0]):
                    data = {"id" : x["id"] , "username" : str(toolkit.g.userobj.id), "role" : userOrgRole}
                    toolkit.get_action("organization_member_create")({'ignore_auth': True}, data)
                    orgChecker = True

            if (not orgChecker):
                data = {"name" : saml_attributes["member"][0].replace(' ', '-').lower(), "title": saml_attributes["member"][0], "state" : "active", "users": [{"name" : str(toolkit.g.userobj.id), "capacity": userOrgRole}]}
                toolkit.get_action("organization_create")({'ignore_auth': True},data)
        except:
            log.exception("Users without group logged in")
        return resp
