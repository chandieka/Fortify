import json
import requests

import fortify.plugins as fp
from fortify.plugins import FortifyPlugin
from fortify.plugins.utils import FortifyPluginUtils
from fortify.errors import FortifyHTTPError

class SNMPTrapPlugin(FortifyPlugin):
    _name = "fortigate_license"
    _option_requirement = dict()
    _description = "This plugin check if the device have all its license are valid"

    def action(self):
        super(SNMPTrapPlugin, self).action()

        fpu = FortifyPluginUtils(
            self._options,
            self._target_host,
            self._result
        )
        
        API_ROUTE = "/api/v2/monitor/license/status"

        valid_status = [
            "licensed",
            "valid",
            "registered",
            "expires_soon",
            "free_license"
        ]

        fpu.set_success()

        try:
            if fpu.is_host_managed():
                manager = self._target_host.manager
                device_name = self._target_host.target_name

                json_res = manager.proxy_call(device_name, API_ROUTE)
                self._result["request_response"].append(json_res)
                fpu.check_http_errors(json_res)
            else:
                HOST_IP, HOST_PORT, HOST_API_KEY = fpu.get_host_info() 
                API_URL = f"https://{HOST_IP}:{HOST_PORT}{API_ROUTE}?access_token={HOST_API_KEY}"
    
                # attempt to make api request to the host 
                res = requests.get(API_URL, verify=False, timeout=1)
                # decode the response to json
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

        if json_res.get("results"):
            # check every "licence" feature
            for licence_name, licence_desc in json_res.get('results').items():
                status = licence_desc.get("status", "")
                # check if status is valid otherwise fail the test
                if status and status.lower() not in valid_status:
                    fpu.fail_plugin(
                        msg=f"{licence_name} has no valid licence, current status: {status}"
                    )
        else:
            fpu.fail_plugin(
                msg="No licences feature can be found!"
            )

        return self._result
        
    