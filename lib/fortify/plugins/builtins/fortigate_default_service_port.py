import json
import requests

import fortify.plugins as fp
from fortify.plugins import FortifyPlugin
from fortify.plugins.utils import FortifyPluginUtils
from fortify.errors import FortifyHTTPError

class DefaultServicePortPlugin(FortifyPlugin):
    """
    Test plugin class to test the functionality of the plugin system
    """
    _name = "default_service_port"
    _option_requirement = dict(
        ssh_port=dict(type=list, required=True, default=[22, 2222]),
        http_port=dict(type=list, required=True, default=[80, 8080, 8888]),
        https_port=dict(type=list, required=True, default=[443, 4433, 4443]),
    )
    _description = "This plugin check if the default service is still using default port number."

    def action(self):
        super(DefaultServicePortPlugin, self).action()

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
            for ssh_port in self._options.get("ssh_port"):
                if global_config.get("admin-ssh-port") == ssh_port:
                    fpu.fail_plugin(
                        msg=f"SSH service is using common default port {ssh_port}"
                    )
            for https_port in self._options.get("https_port"):    
                if global_config.get("admin-sport") == https_port:
                    fpu.fail_plugin(
                        msg=f"HTTPS service is using common default port {https_port}"
                    )
            for http_port in self._options.get("http_port"):    
                if global_config.get("admin-port") == http_port:
                    fpu.fail_plugin(
                        msg=f"HTTP service is using common default port {http_port}"
                    )
        return self._result
    