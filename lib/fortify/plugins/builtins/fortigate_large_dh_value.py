import json
import requests

import fortify.plugins as fp
from fortify.plugins import FortifyPlugin
from fortify.plugins.utils import FortifyPluginUtils
from fortify.errors import FortifyHTTPError

class LargeDHValuePlugin(FortifyPlugin):
    """
    Test plugin class to test the functionality of the plugin system
    """
    _name = "large_dh_value"
    _option_requirement = dict()
    _description = "this plugin check if the device has large Diffie-Hellman values, max is 8192"

    def action(self):
        super(LargeDHValuePlugin, self).action()

        fpu = FortifyPluginUtils(
            self._options,
            self._target_host,
            self._result
        )
        
        API_ROUTE = "/api/v2/cmdb/system/global"

        fpu.set_success()

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

        if global_config.get("dh-params") == 8192:
            fpu.success_plugin(
                msg="Diffie-Hellman params is set to the max value"
            )
        else:
            fpu.fail_plugin(
                msg=f"Diffie-Hellman params is set to {global_config.get('dh-params')}, which is not the max"
            )

        return self._result
    