import json
import requests

import fortify.plugins as fp
from fortify.plugins import FortifyPlugin
from fortify.plugins.utils import FortifyPluginUtils
from fortify.errors import FortifyHTTPError

class EnableTrustedhostsPlugin(FortifyPlugin):
    _name = "enable_trusted_hosts"
    _option_requirement = dict()
    _description = "this plugin will check every admin account if they have trusted host configured"

    def action(self):
        """
        docstring
        """
        super(EnableTrustedhostsPlugin, self).action()
        fpu = FortifyPluginUtils(
            self._options,
            self._target_host, 
            self._result
        )

        API_ROUTE = f"/api/v2/cmdb/system/admin"

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

        for admin in admins:
            counter = 1
            while counter <= 10:
                if admin.get(f"trusthost{counter}") != "0.0.0.0 0.0.0.0":
                    fpu.success_plugin(
                        msg=f"admin {admin.get('name')} has trusted host configured"
                    )
                    break
                counter = counter + 1
            else:
                fpu.fail_plugin(
                    msg=f"admin {admin.get('name')} has no trusted host configured"
                )

        return self._result
    