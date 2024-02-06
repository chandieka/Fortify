import json
import requests

import fortify.plugins as fp
from fortify.plugins import FortifyPlugin
from fortify.plugins.utils import FortifyPluginUtils
from fortify.errors import FortifyHTTPError

class BreakglassPlugin(FortifyPlugin):
    _name = "breakglass"
    _option_requirement = dict(
        admin_name=dict(
            type=str, required=True, default="simac-op"),
        automation_stitch_name=dict(
            type=str, required=True, default="Detected breakglass admin login")
    )
    _description = "This plugin check if the device has been configured with the Breakglass policy."

    def action(self):
        super(BreakglassPlugin, self).action()

        fpu = FortifyPluginUtils(
            self._options,
            self._target_host,
            self._result
        )

        BREAKGLASS_ADMIN_USERNAME = self._options.get("admin_name")
        BREAKGLASS_AUTOMATION_STITCH_NAME = self._options.get("automation_stitch_name")

        ADMIN_API_ROUTE = f"/api/v2/cmdb/system/admin"
        AUTOMATION_STITCH_API_ROUTE = f"/api/v2/cmdb/system/automation-stitch"

        fpu.set_success()

        try:
            if fpu.is_host_managed():
                manager = self._target_host.manager
                device_name = self._target_host.target_name

                admin_json_res = manager.proxy_call(
                    device_name, 
                    ADMIN_API_ROUTE
                )
                self._result["request_response"].append(admin_json_res)

                automation_json_res = manager.proxy_call(
                    device_name,
                    AUTOMATION_STITCH_API_ROUTE,
                )
                self._result["request_response"].append(automation_json_res)
            else:
                HOST_IP, HOST_PORT, HOST_API_KEY = fpu.get_host_info() 

                ADMIN_API_URL = f"https://{HOST_IP}:{HOST_PORT}{ADMIN_API_ROUTE}?access_token={HOST_API_KEY}"
                AUTOMATION_STITCH_API_URL = f"https://{HOST_IP}:{HOST_PORT}{AUTOMATION_STITCH_API_ROUTE}?access_token={HOST_API_KEY}"
        
                admin_res = requests.get(ADMIN_API_URL, verify=False, timeout=1)
                admin_json_res = admin_res.json()
                self._result["request_response"].append(admin_json_res)

                automation_res = requests.get(AUTOMATION_STITCH_API_URL, verify=False, timeout=1)
                automation_json_res = automation_res.json()
                self._result["request_response"].append(automation_json_res)
        except FortifyHTTPError as e:
            return fpu.skip_plugin(
                msg=str(e)
            )
        except Exception as e:
            return fpu.fail_plugin(
                msg=str(e)
            )

        for admin in admin_json_res.get("results"):
            if admin.get("name") == BREAKGLASS_ADMIN_USERNAME:
                fpu.add_message(
                    msg=f"{BREAKGLASS_ADMIN_USERNAME} admin is present"
                )
                break
        else:
            fpu.fail_plugin(
                msg=f"{BREAKGLASS_ADMIN_USERNAME} admin is not present"
            )
        
        for automation_stitch in automation_json_res.get("results"):
            if automation_stitch.get("name") == BREAKGLASS_AUTOMATION_STITCH_NAME:
                fpu.add_message(
                    msg=f"{BREAKGLASS_AUTOMATION_STITCH_NAME} automation trigger is present"
                )
                break
        else:
            fpu.fail_plugin(
                msg=f"{BREAKGLASS_AUTOMATION_STITCH_NAME} automation trigger is not present"
            )

        return self._result
    