import json
import requests

import fortify.plugins as fp
from fortify.plugins import FortifyPlugin
from fortify.plugins.utils import FortifyPluginUtils
from fortify.errors import FortifyHTTPError

class DnsRatingErrorPlugin(FortifyPlugin):
    _name = "dns_rating_error"
    _option_requirement = dict(
        request_allowed=dict(type=bool, required=True, default=True),
    )
    _description = "This plugin will check whether the target host has 'allowed bypass when dns rating error occured' configuration is in placed"
    def action(self):
        """
        docstring
        """
        super(DnsRatingErrorPlugin, self).action()

        fpu = FortifyPluginUtils(
            self._options,
            self._target_host,
            self._result
        )

        # set constant variables
        API_ROUTE = "/api/v2/cmdb/dnsfilter/profile"
        
        fpu.set_success()

        try:
            if fpu.is_host_managed():
                manager = self._target_host.manager
                device_name = self._target_host.target_name
                
                json_res = manager.proxy_call(device_name, API_ROUTE)
                self._result["request_response"].append(json_res)
                fpu.check_http_errors(json_res)
            else:
                HOST_IP, HOST_PORT, HOST_API_KEY = fpu.get_host_info()
                API_URL = f"https://{HOST_IP}:{HOST_PORT}{API_ROUTE}?access_token={HOST_API_KEY}"
                
                # attempt to make api request to the host 
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
        
        # check if no dnsfilter profile exist
        if json_res.get('results'):
            # check every profile
            for dns_profile in json_res.get("results"):
                if self._options.get("request_allowed"):
                    if "error-allow" not in dns_profile.get("ftgd-dns").get("options", ""):
                        fpu.fail_plugin(
                            msg=f"{dns_profile.get('name')} profile do not allow DNS request on rating error"
                        )
                    else:
                        fpu.add_message(
                            msg=f"{dns_profile.get('name')} profile do allow DNS request on rating error"
                        )
                else:
                    if "error-allow" in dns_profile.get("ftgd-dns").get("options", ""):
                        fpu.fail_plugin(
                            msg=f"{dns_profile.get('name')} profile do allow DNS request on rating error"
                        )
                    else:
                        fpu.add_message(
                            msg=f"{dns_profile.get('name')} profile do not allow DNS request on rating error"
                        )
                    
        else:
            fpu.fail_plugin(
                msg="No dns profile found!"
            )

        return self._result