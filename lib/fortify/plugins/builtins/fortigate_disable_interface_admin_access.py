import json
import requests

import fortify.plugins as fp
from fortify.plugins import FortifyPlugin
from fortify.plugins.utils import FortifyPluginUtils
from fortify.errors import FortifyHTTPError, FortifyPluginOptionErrors

class DisableInterfaceAdminAccessPlugin(FortifyPlugin):
    _name = "disable_interface_admin_access"
    _option_requirement = dict(
        role=dict(type=str, required=True, default="wan"),
        forbid_access=dict(type=list, required=True, default=['http', 'https', 'ssh', 'telnet', 'ping']),
    )
    _description = "Check if the device disable administrative access to the external (Internet-facing) interface"
    _protocols = ['http', 'https', 'ssh', 'telnet', 'ping']
    
    def load_preq(self, options, target_host):
        super().load_preq(options, target_host)

        if options.get("role") not in ["wan", "lan"]:
            raise FortifyPluginOptionErrors(f"role options must be either 'wan' or 'lan', cannot be {options.get('role')}")
        
        if not set(options.get("forbid_access")).issubset(self._protocols):
            raise FortifyPluginOptionErrors(f"allow_access options must be either 'http', 'https', 'ssh', 'telnet' or 'ping', cannot be {options.get('forbid_access')}")

    def action(self):
        super(DisableInterfaceAdminAccessPlugin, self).action()

        fpu = FortifyPluginUtils(
            self._options,
            self._target_host,
            self._result
        )

        API_ROUTE = "/api/v2/cmdb/system/interface"

        fpu.set_success()

        try:
            if fpu.is_host_managed():
                # TODO: adjust for fortigate managed by fortimanager
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
        
        for interface in json_res.get("results"):
            interface_role = interface.get("role")
            if interface_role == self._options.get("role"):
                allow_access = interface.get("allowaccess")
                for protocol in self._options.get("forbid_access"):
                    if protocol in allow_access:
                        fpu.fail_plugin(
                            msg=f"{protocol} is accessible from external interface {interface.get('name')}"
                        )
        if fpu.is_success():
            fpu.success_plugin(
                msg="External interface has no access to HTTP, HTTPS, SSH, TELNET, and PING"
            )
        return self._result
    