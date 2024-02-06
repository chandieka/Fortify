import json
import requests

import fortify.plugins as fp
from fortify.plugins import FortifyPlugin
from fortify.plugins.utils import FortifyPluginUtils
from fortify.errors import FortifyHTTPError, FortifyPluginOptionErrors

class DisableUnusedInterfacePlugin(FortifyPlugin):
    _name = "disable_unused_interface"
    _option_requirement = dict(
        ipv4=dict(type=bool, required=True, default=True),
        ipv6=dict(type=bool, required=True, default=False),
    )
    _description = "This plugin check if unused interface (Link is down) is disabled."
    
    def action(self):
        super(DisableUnusedInterfacePlugin, self).action()

        # FortifyPlguinUtils is the abstraction interface for the code 
        fpu = FortifyPluginUtils(
            self._options,
            self._target_host, 
            self._result,
        )

        API_ROUTE = "/api/v2/cmdb/system/interface"
        CRITERIA_IPV4 = "0.0.0.0 0.0.0.0"
        CRITERIA_IPV6 = "::/0"

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
        
        interfaces = json_res.get("results")
        
        for interface in interfaces:
            # check IPv4
            if self._options.get("ipv4"):
                if interface.get("ip") == CRITERIA_IPV4 and interface.get("status") != "down":
                    fpu.fail_plugin(
                        msg=f"interface {interface.get('name')} ipv4 is unused and is not disabled"
                    )
            # check IPv6
            if self._options.get("ipv6"):
                if interface.get("ipv6").get("ip6-address") == CRITERIA_IPV6 and interface.get("status") != "down":
                    fpu.fail_plugin(
                        msg=f"interface {interface.get('name')} ipv6 is unused and is not disabled"
                    )

        return self._result
    