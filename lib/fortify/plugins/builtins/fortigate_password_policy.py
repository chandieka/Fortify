import json
import requests

import fortify.plugins as fp
from fortify.plugins import FortifyPlugin
from fortify.plugins.utils import FortifyPluginUtils
from fortify.errors import FortifyHTTPError, FortifyPluginOptionErrors

class PasswordPolicyPlugin(FortifyPlugin):
    _name = "password_policy"
    _option_requirement = dict(
        minimum_length=dict(type=int, required=True),
        min_lower_case_letter=dict(type=int, required=True),
        min_upper_case_letter=dict(type=int, required=True),
        min_non_alphanumeric=dict(type=int, required=True),
        min_number=dict(type=int, required=True),
        reuse_password=dict(type=bool, required=True, default=False)
    )
    _description = "This plugin check if the password policy match the provided one."
    
    def action(self):
        super(PasswordPolicyPlugin, self).action()

        fpu = FortifyPluginUtils(
            self._options,
            self._target_host,
            self._result
        )

        API_ROUTE = "/api/v2/cmdb/system/password-policy"

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
        
        password_policy = json_res.get("results")

        if password_policy.get("status") == "enable":
            if password_policy.get("minimum-length") != self._options.get("minimum_length"):
                fpu.fail_plugin(
                    msg=f"Password policy minimum lenght is set too {password_policy.get('minimum-length')}, should have been {self._options.get('minimum_length')}"
                )
            if password_policy.get("min-lower-case-letter") != self._options.get("min_lower_case_letter"):
                fpu.fail_plugin(
                    msg=f"Password policy minimum lower case letter is set too {password_policy.get('min-lower-case-letter')}, should have been {self._options.get('min_lower_case_letter')}"
                )
            if password_policy.get("min-upper-case-letter") != self._options.get("min_upper_case_letter"):
                fpu.fail_plugin(
                    msg=f"Password policy minimum upper case letter is set too {password_policy.get('min-upper-case-letter')}, should have been {self._options.get('min_upper_case_letter')}"
                )
            if password_policy.get("min-non-alphanumeric") != self._options.get("min_non_alphanumeric"):
                fpu.fail_plugin(
                    msg=f"Password policy minimum non-alphanumeric letter is set too {password_policy.get('min-non-alphanumeric')}, should have been {self._options.get('min_non_alphanumeric')}"
                )                
            if password_policy.get("min-number") != self._options.get("min_number"):
                fpu.fail_plugin(
                    msg=f"Password policy minimum number character is set too {password_policy.get('min-number')}, should have been {self._options.get('min_number')}"
                )          

            if self._options.get('reuse_password'):
                reused = "enable"
            else:
                reused = "disable"

            if password_policy.get("reuse-password") != reused:
                fpu.fail_plugin(
                    msg=f"Password policy password reuse is not set to {reused}"
                )

        else:
            fpu.fail_plugin(
                msg="Password policy is not enabled"
            )
        
        if fpu.is_success():
            fpu.add_message("Password policy met all the criteria")

        return self._result
    