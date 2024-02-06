import os
import json

import fortify.plugins as fp
from fortify.errors import FortifyHTTPError
from fortify.inventory.fortimanager_host import FortiManagerHost
from fortify.utils.logger import logger

class FortifyPluginUtils():
    """
    A utility class to abstract the interaction between the plugin and the main application.
    """
    def __init__(self, plugin_options, target, results):
        self.plugin_options = plugin_options
        self.target = target
        self.results = results

    def get_host_info(self):
        """
        Return basic information about the host
        """
        HOST_IP = self.target.get_host_name()
        HOST_PORT = self.target.get_host_port()
        HOST_API_KEY = self.target.get_api_key()

        return HOST_IP, HOST_PORT, HOST_API_KEY
    
    def json_output(self):
        """
        convert the passed key value pair arguement as a JSON
        """
        return json.dumps(self.results, indent=4)
    
    def raw_output(self):
        """
        Return the raw result as is
        """
        return self.results
    
    def is_host_managed(self) -> bool:
        """
        Check if the target is managed by a fortimanager
        """
        if self.target.manager is not None and type(self.target.manager) is FortiManagerHost:
            return True
        else:
            return False
        
    def check_http_errors(self, response) -> bool | None:
        """
        Check for common HTTP errors, it will throw an exception if its not a code 200
        """
        if response.get("http_status") == 400:	
            raise FortifyHTTPError(
                "Bad Request: Request cannot be processed by the API")
        elif response.get("http_status") == 401:	
            raise FortifyHTTPError(
                "Not Authorized: Request without successful login session")
        elif response.get("http_status") == 403:
            raise FortifyHTTPError(
                "Forbidden: Request is missing CSRF token or administrator is missing access profile permissions.")
        elif response.get("http_status") == 404:
            raise FortifyHTTPError(
                "Resource Not Found: Unable to find the specified resource.")
        elif response.get("http_status") == 405:	
            raise FortifyHTTPError(
                "Method Not Allowed: Specified HTTP method is not allowed for this resource.")
        elif response.get("http_status") == 413:	
            raise FortifyHTTPError(
                "Request Entity Too Large: Request cannot be processed due to large entity.")
        elif response.get("http_status") == 424:	
            raise FortifyHTTPError(
                "Failed Dependency: Fail dependency can be duplicate resource, missing required parameter, missing required attribute, invalid attribute value.")
        elif response.get("http_status") == 429:	
            raise FortifyHTTPError(
                "Access temporarily blocked: Maximum failed authentications reached. The offended source is temporarily blocked for certain amount of time.")
        elif response.get("http_status") == 500:	
            raise FortifyHTTPError(
                "Internal Server Error: Internal error when processing the request.")
        else:
            return True
    
    def skip_plugin(self, msg: str):
        self.results["status"] = fp.PLUGIN_STATUS_SKIPPED
        self.results["message"].append(msg)

        return self.results
    
    def success_plugin(self, msg: str):
        self.results["status"] = fp.PLUGIN_STATUS_SUCCESS
        self.results["message"].append(msg)

        return self.results
    
    def fail_plugin(self, msg: str):
        self.results["status"] = fp.PLUGIN_STATUS_FAIL
        self.results["message"].append(msg)

        return self.results
    
    def add_message(self, msg: str):
        self.results["message"].append(msg)

        return self.results
    
    def is_success(self):
        return self.results["status"] == fp.PLUGIN_STATUS_SUCCESS

    def is_fail(self):
        return self.results["status"] == fp.PLUGIN_STATUS_FAIL

    def is_skip(self):
        return self.results["status"] == fp.PLUGIN_STATUS_SKIPPED
    
    def set_success(self):
        self.results["status"] = fp.PLUGIN_STATUS_SUCCESS

    def set_fail(self):
        self.results["status"] = fp.PLUGIN_STATUS_FAIL

    def set_skip(self):
        self.results["status"] = fp.PLUGIN_STATUS_SKIPPED
    