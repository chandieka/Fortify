import json
import requests

import fortify.plugins as fp
from fortify.plugins import FortifyPlugin
from fortify.plugins.utils import FortifyPluginUtils
from fortify.errors import FortifyHTTPError

class AdminPermissionPlugin(FortifyPlugin):
    _name = "admin_permission"
    _option_requirement = dict(
        account_names=dict(type=list, required=True),
        permission=dict(type=str, required=True, default="read-write"),
    )
    _description = "This plugin check if X account have been set with Y permission on the device. X is the name of the account. Y is the permission level."

    def action(self):
        super(AdminPermissionPlugin, self).action()

        fpu = FortifyPluginUtils(
            self._options,
            self._target_host, 
            self._result
        )

        HOST_IP, HOST_PORT, HOST_API_KEY = fpu.get_host_info() 

        ACCPROFILE_API_ROUTE = "/api/v2/cmdb/system/accprofile"
        ADMIN_API_ROUTE = f"/api/v2/cmdb/system/admin"

        permission_type = [
            "secfabgrp",
            "ftviewgrp",
            "authgrp",
            "sysgrp",
            "netgrp",
            "loggrp",
            "fwgrp",
            "vpngrp",
            "utmgrp",
            "wifi",
        ]        

        fpu.set_success()

        try:
            if fpu.is_host_managed():
                manager = self._target_host.manager
                device_name = self._target_host.target_name

                accprofile_json_res = manager.proxy_call(
                    device_name, ACCPROFILE_API_ROUTE
                )
                self._result["request_response"].append(accprofile_json_res)
                fpu.check_http_errors(accprofile_json_res)

                admin_json_res = manager.proxy_call(
                    device_name, ADMIN_API_ROUTE
                )
                self._result["request_response"].append(admin_json_res)
                fpu.check_http_errors(admin_json_res)
            else:
                API_URL = f"https://{HOST_IP}:{HOST_PORT}{ACCPROFILE_API_ROUTE}?access_token={HOST_API_KEY}"
                ADMIN_API_URL = f"https://{HOST_IP}:{HOST_PORT}{ADMIN_API_ROUTE}?access_token={HOST_API_KEY}"

                accprofile_res = requests.get(API_URL, verify=False, timeout=1)
                accprofile_json_res = accprofile_res.json()
                self._result["request_response"].append(accprofile_json_res)
                fpu.check_http_errors(accprofile_json_res)

                admin_res = requests.get(ADMIN_API_URL, verify=False, timeout=1)
                admin_json_res = admin_res.json()
                self._result["request_response"].append(admin_json_res)
                fpu.check_http_errors(admin_json_res)
        except FortifyHTTPError as e:
            return fpu.skip_plugin(
                msg=str(e)
            )
        except Exception as e:
            return fpu.fail_plugin(
                msg=str(e)
            )
        
        account_profiles = accprofile_json_res.get("results")
        admins = admin_json_res.get("results")
        
        # iterate over the specified admin name(s)
        for name in self._options.get("account_names"):
            # check in the fetch list if the admins exist
            for admin in admins:
                if admin.get("name") == name:
                    # fetch the accprofile of the admin
                    accprofile_name= admin.get("accprofile")
                    # fetch the permission level of the accprofile
                    accprofile = self.get_permission(account_profiles, accprofile_name)
                    self._result["message"].append(f"{name} admin is present")
                    # check the permission
                    for type in permission_type:
                        if accprofile.get(type) != self._options.get("permission"):
                            fpu.fail_plugin(
                                msg=f"admin {name} have {type} set to {accprofile.get(type)}"
                            )
                    break
            else:
                fpu.fail_plugin(
                    msg=f"{name} admin is not present"
                )

        return self._result
    
    def get_permission(self, accprofile_list, accprofile_name):
        for accprofile in accprofile_list:
            if accprofile.get("name") == accprofile_name:
                return accprofile
