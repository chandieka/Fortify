import json
import requests

import fortify.plugins as fp
from fortify.plugins import FortifyPlugin
from fortify.plugins.utils import FortifyPluginUtils
from fortify.errors import FortifyHTTPError

class MultipleAdminAccountPlugin(FortifyPlugin):
    """
    Test plugin class to test the functionality of the plugin system
    """
    _name = "multiple_admin_account"
    _option_requirement = dict()
    _description = "this plugin will check the device if it has more then one admin account"

    def action(self):
        super(MultipleAdminAccountPlugin, self).action()

        fpu = FortifyPluginUtils(
            self._options,
            self._target_host,
            self._result
        )

        API_ROUTE = f"/api/v2/cmdb/system/admin"
        
        self._result["status"] = fp.PLUGIN_STATUS_SUCCESS
        self._result["is_compliance"] = True

        try:
            if fpu.is_host_managed():
                manager = self._target_host.manager
                device_name = self._target_host.target_name

                json_res = manager.proxy_call(
                    device_name, 
                    API_ROUTE
                )
                self._result["request_response"].append(json_res)
                fpu.check_http_errors(json_res)
            else:
                HOST_IP, HOST_PORT, HOST_API_KEY = fpu.get_host_info() 
                API_URL = f"https://{HOST_IP}:{HOST_PORT}{API_ROUTE}?access_token={HOST_API_KEY}"

                res = requests.get(url=API_URL, verify=False, timeout=1)
                json_res = res.json()
                
                self._result["request_response"].append(json_res)
                fpu.check_http_errors(json_res)
        except FortifyHTTPError as e:
            return fpu.skip_plugin(
                msg=str(e)
            )
        except Exception as e:
            return fpu.fail_plugin(
                msg=str(e)
            )

        admins = json_res.get("results")

        if len(admins) > 1:
            fpu.success_plugin(
                msg="The device has more then one admin account"
            )
        else:
            fpu.fail_plugin(
                msg="The device has only one admin account"
            )

        return self._result
    