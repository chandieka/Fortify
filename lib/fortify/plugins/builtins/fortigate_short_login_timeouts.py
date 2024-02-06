import json
import requests

import fortify.plugins as fp
from fortify.plugins import FortifyPlugin
from fortify.plugins.utils import FortifyPluginUtils
from fortify.errors import FortifyHTTPError

class ShortLoginTimeoutsPlugin(FortifyPlugin):
    """
    Test plugin class to test the functionality of the plugin system
    """
    _name = "short_login_timeouts"
    _option_requirement = dict(
        ssh_timeout=dict(type=int, required=True, default=30),
        admin_timeout=dict(type=int, required=True, default=5),
    )
    _description = "this plugin check if admin session has short login timeout"

    def action(self):
        super(ShortLoginTimeoutsPlugin, self).action()

        fpu = FortifyPluginUtils(
            self._options,
            self._target_host,
            self._result
        )

        API_ROUTE = "/api/v2/cmdb/system/global"

        self._result["status"] = fp.PLUGIN_STATUS_SUCCESS

        try:
            if fpu.is_host_managed():
                manager = self._target_host.manager
                device_name = self._target_host.target_name

                json_res = manager.proxy_call(
                    device_name, API_ROUTE
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
        
        global_config = json_res.get("results")

        self._result["status"] = fp.PLUGIN_STATUS_SUCCESS

        if global_config:
            if global_config.get("admintimeout") < self._options.get("admin_timeout"):
                fpu.fail_plugin(
                    msg=f"Admin web access timeout is shorter then {self._options.get('admin_timeout')}"
                )
                
            if global_config.get("admin-ssh-grace-time") < self._options.get("ssh_timeout"):
                fpu.fail_plugin(
                    msg=f"Admin ssh access timeout is shorter then {self._options.get('ssh_timeout')}"
                )

            if fpu.is_success():
                fpu.success_plugin(
                    msg=f"Admin ssh access timeout is set too {global_config.get('admin-ssh-grace-time')}"
                )
                fpu.success_plugin(
                    msg=f"Admin web access timeout is set too {global_config.get('admintimeout')}"
                )

        return self._result
    