import json
import requests

import fortify.plugins as fp
from fortify.plugins import FortifyPlugin
from fortify.plugins.utils import FortifyPluginUtils
from fortify.errors import FortifyHTTPError

class SNMPTrapPlugin(FortifyPlugin):
    _name = "snmp_trap"
    _option_requirement = dict(
        enabled_events=dict(type=list, required=True),
        disabled_events=dict(type=list, required=True),
    )
    _description = "This plugin check if selected SNMP traps are either enabled or disabled."

    def action(self):
        super(SNMPTrapPlugin, self).action()

        fpu = FortifyPluginUtils(
            self._options,
            self._target_host,
            self._result
        )
        
        API_ROUTE = "/api/v2/cmdb/system.snmp/community"

        try:
            if fpu.is_host_managed():
                manager = self._target_host.manager
                device_name = self._target_host.target_name

                json_res = manager.proxy_call(device_name, API_ROUTE)
                self._result["request_response"].append(json_res)
                fpu.check_http_errors(json_res)
            else:
                # attempt to make api request to the host 
                HOST_IP, HOST_PORT, HOST_API_KEY = fpu.get_host_info() 
                API_URL = f"https://{HOST_IP}:{HOST_PORT}{API_ROUTE}?access_token={HOST_API_KEY}"

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
        
        # set default status to success
        self._result["status"] = fp.PLUGIN_STATUS_SUCCESS

        # check if there any snmp profile present
        if len(json_res.get("results")) > 0:
            for snmp_profile in json_res.get('results'):
                # get the current list snmp event string
                events = snmp_profile.get('events') # str value return
                # check for enabled events
                for enabled_event in self._options.get("enabled_events"):
                    if enabled_event not in events:
                        fpu.fail_plugin(
                            msg=f"{enabled_event} event is not enabled"
                        )
                # check for disabled events
                for disabled_event in self._options.get("enabled_events"):
                    if disabled_event not in events:
                        fpu.fail_plugin(
                            msg=f"{disabled_event} event is not disabled"
                        )
        else:
            fpu.fail_plugin(
                msg="SNMP profile have not been configured"
            )

        if fpu.is_success():
            fpu.add_message("All SNMP Traps are configured as specified")

        return self._result
    