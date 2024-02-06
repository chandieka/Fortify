import requests

from fortify.errors import FortifyHTTPError
from fortify.plugins import FortifyPlugin
from fortify.plugins.utils import FortifyPluginUtils

class FortiGateIsAlivePlugin(FortifyPlugin):
    _name = "is_alive"
    _option_requirement = dict()
    _description = "Check if the fortigate firewall is alive"

    def action(self):
        super(FortiGateIsAlivePlugin, self).action()

        fpu = FortifyPluginUtils(
            self._options,
            self._target_host,
            self._result
        )

        HOST_IP, HOST_PORT, HOST_API_KEY = fpu.get_host_info()

        API_ROUTE = "/api/v2/cmdb/system/status"

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
        
        if json_res.get("http_status") == 200:
            fpu.success_plugin("The Fortigate is alive!")
        else:
            fpu.fail_plugin("The Fortigate is Dead!")

        return fpu.raw_output()
