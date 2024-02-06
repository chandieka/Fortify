import json
import requests

import fortify.plugins as fp
from fortify.plugins import FortifyPlugin
from fortify.plugins.utils import FortifyPluginUtils
from fortify.errors import FortifyHTTPError

class AdminTrustedhostsPlugin(FortifyPlugin):
    _name = "admin_trusted_hosts"
    _option_requirement = dict(
        admin_names=dict(type=list, required=True),
        trusted_hosts=dict(type=list, required=True),
    )
    _description = "this plugin will check an admin account has their trusted host configured correctly"

    def action(self):
        """
        docstring
        """
        super(AdminTrustedhostsPlugin, self).action()
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

        fpu.set_success()

        admins = json_res.get("results")
        admin_names = self._options.get("admin_names")
        filtered_admin = [admin for admin in admins if admin.get("name") in admin_names]

        for admin in filtered_admin:
            counter = 1
            for host in self._options.get("trusted_hosts", []):
                while counter <= 10:
                    trust_host = admin.get(f"trusthost{counter}")
                    if host == trust_host:
                        fpu.add_message(
                            msg=f"admin {admin.get('name')} has {host} confgured as trustedhost{counter}"
                        )
                        break
                    counter = counter + 1
                else:
                    fpu.fail_plugin(
                        msg=f"admin {admin.get('name')} has not configured {host} trusted host"
                    )

        return self._result
    