import json
import requests

import fortify.plugins as fp
from fortify.plugins import FortifyPlugin
from fortify.plugins.utils import FortifyPluginUtils
from fortify.errors import FortifyHTTPError

class DefaultAdminNamePlugin(FortifyPlugin):
    _name = "default_admin_name"
    _option_requirement = dict()
    _description = "this plugin check if the default admin is still name admin"

    def action(self):
        """
        docstring
        """
        super(DefaultAdminNamePlugin, self).action()
        fpu = FortifyPluginUtils(
            self._options,
            self._target_host,
            self._result
        )

        ADMIN_API_ROUTE = f"/api/v2/cmdb/system/admin"
        
        self._result["status"] = fp.PLUGIN_STATUS_SUCCESS
        self._result["is_compliance"] = True

        try:
            if fpu.is_host_managed():
                manager = self._target_host.manager
                device_name = self._target_host.target_name

                json_res = manager.proxy_call(
                    device_name, 
                    ADMIN_API_ROUTE
                )
                self._result["request_response"].append(json_res)
                fpu.check_http_errors(json_res)
            else:
                fpu.skip_plugin(
                    msg="This plugin required the fortigate to be managed by a fortimanager"
                )
                return self._result
        except FortifyHTTPError as e:
            return fpu.skip_plugin(
                msg=str(e)
            )
        except Exception as e:
            return fpu.fail_plugin(
                msg=str(e)
            )

        admins = json_res.get("results")

        for admin in admins:
            if admin.get("name") == "admin" and admin.get("accprofile") == "super_admin":
                fpu.fail_plugin(
                    msg="Default admin is still name admin"
                )
        else:
            fpu.success_plugin(
                msg="Default admin has been renamed to a non default name"
            )

        return self._result
    