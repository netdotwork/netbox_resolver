import pynetbox
import re
import ipaddress
from netmiko import ConnectHandler, NetMikoAuthenticationException


class NetboxIpamResolver:
    def __init__(
        self,
        ip_list=None,
        netbox=None,
        token=None,
        private_key=None,
        threads=None,
        max_workers=None,
        arp=None,
        arp_interfaces=None,
        inventory=None,
        *args,
        **device_params
    ):
        """
        For initialization  you can use the same arguments as in netmiko,
        because it's wrapper.
        Netmiko arguments - https://github.com/ktbyers/netmiko/blob/develop/netmiko/base_connection.py
        New arguments for this method only:

        :ip_list: ip networks and addresses in list format. For many hosts in
        single params dictionary.
        For example: ['10.1.1.1', '10.1,2,3-5.10.1,2,3,4,5,10-125', '10.1.10.1,2,3,4,5,10-125', '10.1.0.0/24']
        :type ip_list: str in list

        Pynetbox arguments (https://github.com/digitalocean/pynetbox)
        :netbox: netbox domain name or ip address.
        For example: 'http://192.168.0.1'
        :type netbox: str

        :token: netbox user token from NetBox Administration > Users > Tokens
        :type token: str

        :private_key: netbox private_key or private_key_file.
        :type private_key: str

        :threads: True or False(None by default). To enable concurrent.futures and threading. It works with
        ip_list only
        :type threads: bool

        :max_workers: number of threads for submit in concurrent.futures
        :type max_workers: int

        :arp: True or False(None by default). To get ip addresses from arp
        cache. To use with arp_interfaces
        :type arp: bool

        :arp_interfaces: for example, ['Vlanif100', 'Vlanif200']. It looks like parser for 'display arp
        interface Vlanif100 and then for Vlanif200. Use this argument to add ip
        addresses from arp to netbox db. Description format - "Added from arp
        cache of {sysname}, interface {interface}"
        :type arp_interface: str in list

        :inventory: True or False(None by default). To get inventory from
        "display elabel" command
        :type inventory: bool
        """
        self.ip_list = ip_list
        self.netbox = netbox
        self.token = token
        self.private_key = private_key
        self.device_params = device_params
        self.threads = threads
        self.max_workers = max_workers
        self.arp = arp
        self.arp_interfaces = arp_interfaces
        self.inventory = inventory
        if ip_list and "ip" in device_params.keys():
            raise ValueError(
                "Erorr in arguments. Don't use 'ip' and 'ip_list' together"
            )
        if ip_list:
            self.ip_list_object = Iterator(self.ip_list, self.device_params)
        if arp or arp_interfaces:
            self._check_arp()

    def _check_arp(self):
        error_message = "Error in arguments, add {}, please"
        var_list = ["arp like a True or False", "arp_interfaces like a list please"]
        var_list1 = [self.arp, self.arp_interfaces]
        for position, k in enumerate(var_list1):
            if not k:
                raise ValueError(error_message.format(var_list[position]))
        if self.arp and self.arp_interfaces:
            if not isinstance(self.arp_interfaces, list):
                raise ValueError("Erorr in arguments, arp_interfaces is list")


# create :ip_list: like iterator
class Iterator:
    def __init__(self, ip_list, device_params):
        self.ip_list = self._check_ip_list_format(ip_list)
        self._index = 0
        self.device_params = device_params

    # this is not best solution for checking :ip_list: format
    def _check_ip_list_format(self, ip_list):
        str_ip_list = []
        params = {
            "single_ip": ipaddress.ip_address,
            "network": ipaddress.ip_network,
            "hard_ip": self._convert_hard_ip,
        }
        # wow! What is a beautiful regex?!;d
        regex = (
            r"(?P<network>\d+(\.\d+){3}/\d+)"
            r"|(?P<hard_ip>\d{1,3}((\.(\d{1,3},){1,}(\d{1,3}-\d{1,3},){1,})(\d{1,3}-\d{1,3})"
            "|(\d{1,3}-\d{1,3},){1,}(\d{1,3}-\d{1,3})"
            "|(\.(\d{1,3},){1,}(\d{1,3}-\d{1,3}))"
            "|\.(\d{1,3},){1,}\d{1,3}"
            "|\.(\d{1,3}-\d{1,3})"
            "|\.(\d){1,3}){3})"
            r"|(?P<single_ip>\d{1,3}(\.\d{1,3}){3})"
        )
        if not all(
            [isinstance(ip_list, list)] + [isinstance(value, str) for value in ip_list]
        ):
            raise ValueError("Error in 'ip_list' argument. Incorrect type.")
        for value in ip_list:
            match = re.search(regex, value)
            if match:
                for param in params:
                    if match.lastgroup == param:
                        try:
                            ip_object = params[param](match.group(match.lastgroup))
                            if param == "network":
                                str_ip_list.extend(
                                    [str(ip) for ip in ip_object.hosts()]
                                )
                            elif param == "single_ip":
                                str_ip_list.append(str(ip_object))
                            elif param == "hard_ip":
                                str_ip_list.extend(ip_object)
                        except ValueError:
                            print(
                                "Error in 'ip_list' argument. Incorrect IPv4 address or IPv4 network"
                            )
                return str_ip_list
            else:
                raise ValueError(
                    "Error in 'ip_list' argument. Incorrect IPv4 address or IPv4 network"
                )

    def _check_hard_ip(self, hard_ip):
        correct_ip_list = [hard_ip.split(".")[0]]
        for value in hard_ip.split(".")[1:]:
            string = ""
            for octet in value.split(","):
                if "-" in octet:
                    string += ",".join(
                        [
                            str(i)
                            for i in range(
                                int(octet.split("-")[0]), int(octet.split("-")[1]) + 1
                            )
                        ]
                    )
                else:
                    string += octet + ","
            correct_ip_list.append(string.rstrip(","))
        return correct_ip_list

    def _convert_hard_ip(self, hard_ip):
        correct_ip_list = self._check_hard_ip(hard_ip)
        full_ip_list = []
        for octet2 in correct_ip_list[1].split(","):
            for octet3 in correct_ip_list[2].split(","):
                for octet4 in correct_ip_list[3].split(","):
                    full_ip_list.append(
                        ".".join([correct_ip_list[0]] + [octet2, octet3, octet4])
                    )
        return full_ip_list

    def __iter__(self):
        return self

    def __next__(self):
        if self._index < len(self.ip_list):
            self.device_params["ip"] = self.ip_list[self._index]
            self._index += 1
            return self.device_params
        else:
            raise StopIteration
