import json
import requests

import fortify.plugins as fp
from fortify.plugins import FortifyPlugin
from fortify.plugins.utils import FortifyPluginUtils
from fortify.errors import FortifyHTTPError

class LatestFirmwareVersionPlugin(FortifyPlugin):
    _name = "latest_firmware_version"
    _option_requirement = dict()
    _description = "This plugin check if the device running the latest firmware"

    def action(self):
        """
        docstring
        """
        super(LatestFirmwareVersionPlugin, self).action()

        # FortifyPlguinUtils is the abstraction interface for the code 
        fpu = FortifyPluginUtils(
            self._options,
            self._target_host,
            self._result
        )
        
        API_ROUTE = "/api/v2/monitor/system/firmware/upgrade-paths"

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
        
        upgrade_paths = json_res.get("results")

        if len(upgrade_paths) > 0:
            latest_version = upgrade_paths[0].get("to")
            version = f"v{latest_version.get('major')}.{latest_version.get('minor')}.{latest_version.get('patch')}"
            fpu.fail_plugin(
                msg=f"The device firmware version ({json_res.get('version')}) is outdated, the latest available version is {version}"
            )
        else:
            fpu.success_plugin(
                msg=f"The device is up-to-date with the latest firmware update, version {json_res.get('version')}"
            )

        return self._result
    