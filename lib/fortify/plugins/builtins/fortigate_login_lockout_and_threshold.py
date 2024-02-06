import json
import requests

import fortify.plugins as fp
from fortify.plugins import FortifyPlugin
from fortify.plugins.utils import FortifyPluginUtils
from fortify.errors import FortifyHTTPError

class LoginLockoutAndThresholdPlugin(FortifyPlugin):
    _name = "login_lockout_and_threshold"
    _option_requirement = dict(
        login_threshold=dict(type=int, required=True, default=10),
        lockout_duration=dict(type=int, required=True, default=2),
    )
    _description = "this plugin check the lockout duration and login threshold value"

    def action(self):
        super(LoginLockoutAndThresholdPlugin, self).action()

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

        if global_config:
            if global_config.get("admin-lockout-threshold") < self._options.get("login_threshold"):
                fpu.fail_plugin(
                    msg=f"Admin max login attempt is set shorter then {self._options.get('login_threshold')} tries"
                )
            else:
                fpu.add_message(f"Admin lockout duration is set to {global_config.get('admin-lockout-duration')} tries")
                
            if global_config.get("admin-lockout-duration") < self._options.get("lockout_duration"):
                fpu.fail_plugin(
                    msg=f"Admin lockout duration is set shorter then {self._options.get('lockout_duration')} minutes"
                )
            else:
                fpu.add_message(f"Admin lockout duration is set to {global_config.get('admin-lockout-duration')} minutes")

        return self._result
    