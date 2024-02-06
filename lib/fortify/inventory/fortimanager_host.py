import requests
import json

from fortify.inventory.host import Host
from fortify.inventory.fortigate_host import FortiGateHost
from  fortify.utils.logger import logger

class FortiManagerHost(Host):
    """
    This class represent a single target host.
    """
    def __init__(
            self, 
            target_name: str, 
            host_name: str, 
            port: int, 
            username: str,
            password: str,
            auto_login=True,
            id=True,
        ):
        """
        Initialize a new target host
        """
        super(FortiManagerHost, self).__init__(
            target_name, 
            host_name,
            port,
            id,
        )
        self._username = username
        self._password = password
        self._session_id = ""
        
        self.adom = []
        self.API_URL = f"https://{self.host_name}:{self.port}/jsonrpc"

        # if auto_login:
        #     self.login()

    def get_session_id(self):
        """Return the API key of this Fortigate"""
        return self._session_id
    
    def login(self) -> bool | None:
        """Login into the fortimanager"""
        headers = {
            "Content-Type": "application/json"
        }
        http_payload = {
            "id": 1,
            "method": "exec",
            "params": [
                {
                    "data": {
                        "passwd": self._password,
                        "user": self._username,
                    },
                    "url": "/sys/login/user"
                }
            ]
        }

        json_payload = json.dumps(http_payload)
        res = requests.post(self.API_URL, data=json_payload, headers=headers)
        json_res = res.json()

        # check if the request is successfull
        results = json_res.get("result")
        for result in results:
            if result.get("status").get("code") == 0:
                self._session_id = json_res.get("session")
            else:
                raise Exception(
                    f"Error: Attempt to login to fortimanager {self.target_name} failed!"
            )

    def logout(self) -> bool | None:
        """logout of the fortimanager"""
        headers = {
            "Content-Type": "application/json"
        }
        http_payload = {
            "id": 1,
            "method": "exec",
            "params": [
                {
                    "url": "/sys/logout"
                }
            ],
            "session": self._session_id,
        }

        json_payload = json.dumps(http_payload)
        res = requests.post(self.API_URL, data=json_payload, headers=headers)
        json_res = res.json()

        results = json_res.get("result")
        # check if the request is successfull
        for result in results:
            if result.get("status").get("code") != 0:
                raise Exception(
                    f"Error: attempt to logout to fortimanager {self.target_name} failed!"
                )

    def get_firewalls_from_adom(self, adom: str) -> list[FortiGateHost]:
        """ 
        return a collection of firewalls from the specified ADOM
        """
        self.login()
        firewalls = []

        headers = {
            "Content-Type": "application/json"
        }
        http_payload = {
            "id": 1,
            "method": "get",
            "params": [
                {
                    "url": f"/dvmdb/adom/{adom}/device"
                }
            ],
            "session": self._session_id,
        }
        
        json_payload = json.dumps(http_payload)
        res = requests.post(self.API_URL, data=json_payload, headers=headers)
        self.logout()
        json_res = res.json()

        # check if the request is successfull
        results= json_res.get("result")
        if results[0].get("status").get("code") == 0:
            for result in results:
                for device in result.get("data"):
                    fg = FortiGateHost(
                        target_name=device.get("name"),
                        manager=self,
                        adom=adom,
                    )
                    firewalls.append(fg)
        else:
            raise Exception("")
        
        total_fg = len(firewalls)
        logger.v(f"OK: Fetch {total_fg} firewalls from {self.target_name} in {adom} adom")

        return firewalls
    
    def proxy_call(self, device_name: str, api_url: str):
        """
        Make proxy API call to a firewall by using this fortimanager 
        """
        self.login()

        headers = {
            "Content-Type": "application/json"
        }
        http_payload = {
            "method": "exec",
            "params": [
                {
                    "data": {
                        "action": "get",
                        "resource": api_url,
                        "target": [
                            f"device/{device_name}"
                        ],
                    },
                    "url": "/sys/proxy/json"
                }
            ],
            "session": self._session_id,
            "id": 1
        }
        json_payload = json.dumps(http_payload)
        
        try:
            res = requests.post(url=self.API_URL, data=json_payload, headers=headers)
            res_json = res.json()
            self.logout()

            return res_json.get("result")[0].get("data")[0].get("response")
        except Exception as e:
            raise Exception(e)
        
    def filter_firewall_by_name(self, firewalls: list[FortiGateHost], filter: list[str]):
        """Return a new list with only FortiGateHost that match the name in the filter list"""
        return [firewall for firewall in firewalls if firewall.get_target_name() in filter]
        
