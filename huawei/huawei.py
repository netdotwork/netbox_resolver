import pynetbox
import os
import re
import ipaddress
import sys
from netmiko import (
    ConnectHandler,
    NetMikoAuthenticationException,
    NetmikoTimeoutException,
)
from netmiko.huawei.huawei import HuaweiBase
from nb_ipam_resolver import NetboxIpamResolver
from pynetbox.core.query import RequestError
from concurrent.futures import (
    ThreadPoolExecutor,
    as_completed,
    Future,
    TimeoutError,
)
from threading import RLock
from datetime import datetime
import time
import logging

logging.getLogger("paramiko").setLevel(logging.WARNING)

logging.basicConfig(
    format="%(threadName)s %(name)s %(levelname)s: %(message)s", level=logging.INFO
)


class HuaweiIpam(NetboxIpamResolver):
    def __init__(self, *args, **device_params):
        super().__init__(*args, **device_params)
        # instantiate the pynetbox API
        self.nb = pynetbox.api(
            self.netbox, private_key_file=self.private_key, token=self.token
        )
        # common parameters which will create by default(for new devices)
        # device_roles - Network device
        # manufacturers - Huawei Technologies
        # platforms - Huawei VRP
        self._global_params = {
            self.nb.dcim.device_roles: (
                {"name": "Network device"},
                {"name": "Network device", "slug": "network_device", "color": "4caf50"},
            ),
            self.nb.dcim.manufacturers: (
                {"name": "Huawei Technologies"},
                {"name": "Huawei Technologies", "slug": "huawei_technologies"},
            ),
            self.nb.dcim.platforms: (
                {"name": "Huawei VRP"},
                {"name": "Huawei VRP", "slug": "huawei-vrp"},
            ),
        }
        # create these default parameters
        self._get_create(self._global_params)

    def send_ip(self):
        """
        Method which works with single device
        For correct work use :ip: argument instead of :ip_list:
        """
        if self.ip_list:
            raise ValueError(
                "Error in arguments. It's only for single device. Please don't use 'ip_list', use 'ip'"
            )
        with ConnectHandler(**self.device_params) as ssh_huawei:
            self._create_all(ssh_huawei, self.device_params["ip"])

    def send_ip_list(self):
        """
        Method which works with many devices
        For correct work use :ip_list: argument instead of :ip:
        Actual arguments:
        :threads: True or False(None by default). To enable concurrent.futures and threading. It works with
        ip_list only
        :type threads: bool

        :max_workers: number of threads for submit in concurrent.futures
        :type max_workers: int
        """
        if "ip" in self.device_params:
            raise ValueError(
                "Erorr in arguments. It's only for many devices. Please don't use 'ip', use 'ip_list' for this method"
            )
        if self.threads:
            result = self._task_queue(
                self._try_create_all, self.ip_list_object, concurrency=self.max_workers
            )
            try:
                while not result.done():
                    try:
                        result.result(0.2)
                        print(
                            "\rdone: {done}, waited: "
                            "{delayed}".format(**result.stats),
                            flush=True,
                        )
                    # check extensions
                    except TimeoutError:
                        pass
                    # sys.stdout.flush()
            # use future.cancel() method as attemption to shutdown executor
            # by Ctrl+C
            except KeyboardInterrupt:
                result.cancel()
                raise

        else:
            for session_params in self.ip_list_object:
                self._try_create_all(session_params, session_params["ip"])
                # try:
                # self._try_create_all(session_params, session_params['ip'])
                # except (NetmikoTimeoutException, NetMikoAuthenticationException) as error:
                # logging.warning(error)
                # continue

    def _try_create_all(self, session_params, device_ip):

        msg_info_connection = " --- > {} Trying to connect to {}"

        msg_info_drop = " --- > {} Unable to connect to {}"

        logging.info(msg_info_connection.format(datetime.now().time(), device_ip))
        try:
            with ConnectHandler(**session_params) as ssh_huawei:
                self._create_all(ssh_huawei, device_ip)
        except (NetmikoTimeoutException, NetMikoAuthenticationException) as error:
            logging.warning(error)
            logging.info(msg_info_drop.format(datetime.now().time(), device_ip))
            return

    def _create_all(self, ssh_session_object, device_ip):
        self._check_net_textfsm()
        # HRP_M & HRP_S for Huawei firewalls in HRP mode
        sysname = re.sub(r"HRP_M|HRP_S|<|>", "", ssh_session_object.find_prompt())
        # site for device binding
        # site is characters before '_' or '.' in sysname without '_' or '.'
        site = re.sub(r"_.*|\..*", "", sysname)
        _model = self._check_model(ssh_session_object)
        # device type -> model name
        model = re.sub(r" ", "_", _model[0]["model"])
        # interfaces list
        interfaces = self._check_interfaces(sysname, ssh_session_object)
        # ip addresses list
        ip_addresses = self._check_ip_addresses(ssh_session_object)

        # Protection from sysname changing

        # If you work with the scheduler and decide to change device sysname
        # after it was added to the NetBox database, this can create a lil
        # problem... Script will try to create a new device with new sysname. So
        # it is better to add protection - in this case, script will not do
        # anything until you match the device sysname and site, sysname in the NetBox database

        # In short, if you change sysname on device, you need to change device name and
        # site in netbox, otherwisethis function returns nothing

        # Delete or comments this block of code if you don't need it
        for item in ip_addresses:
            for address in item.values():
                if device_ip in str(address):
                    mgmt_ip = address[0]
                    ip = self.nb.ipam.ip_addresses.get(address=mgmt_ip)
                    if ip and ip.interface:
                        if str(ip.interface.device) != sysname:
                            return
        # End of protection from sysname changing

        # parameters for checking and creating
        points = {
            self.nb.dcim.device_types: (
                {"model": model},
                {
                    "manufacturer": {"name": "Huawei Technologies"},
                    "model": model,
                    "slug": model,
                },
            ),
            self.nb.dcim.sites: (
                {"slug": f"dc-{site}"},
                {"name": f"dc-{site}", "slug": f"dc-{site}"},
            ),
        }
        device_vars = {
            self.nb.dcim.devices: (
                {"name": sysname},
                {
                    "name": sysname,
                    "device_role": {"name": "Network device"},
                    "device_type": {"model": model},
                    "manufacturer": {"name": "Huawei Technologies"},
                    "site": {"slug": f"dc-{site}"},
                    "platform": {"name": "Huawei VRP"},
                },
            ),
        }
        interfaces_vars = {
            ("G",): 1000,
            ("Virtual", "Vlanif", "LoopBack", "NULL", "Tunnel"): 0,
            ("X",): 1150,
            ("Ethernet", "M"): 800, #"M" - Meth
            ("Eth-Trunk",): 200,
            ("A",): 32767, #"A" - Aux
            ("C",): 2830, #"C" - Cellular
        }
        # check device if it is
        self._update_device(
            device_vars,
            points,
            model,
            f"dc-{site}",
            sysname,
            interfaces,
            interfaces_vars,
        )
        # create new device with default parameters
        self._create_device(device_vars, points, sysname, interfaces, interfaces_vars)
        # create new VRF's and update existing VRF's
        self._create_vrfs(ssh_session_object)
        # create new prefixes and ip addresses and delete the incorrect ones
        self._create_prefixes_ip_addresses(
            ip_addresses, sysname, device_ip, ssh_session_object
        )
        # create serial (if software supports 'display esn' command)
        self._check_serial(ssh_session_object, sysname)

        # it works with :arp: and :arp_interfaces:
        if self.arp and self.arp_interfaces:
            self._create_addresses_from_arp_cache(ssh_session_object, sysname)
        # it works with :inventory:
        if self.inventory:
            self._create_inventory(ssh_session_object, sysname)

    def _update_serial(self, serial, sysname):
        dev = self.nb.dcim.devices.filter(name=sysname)[0]
        if dev.serial != serial:
            dev.update({"serial": serial})

    def _check_serial(self, ssh_session_object, sysname):
        serial = ssh_session_object.send_command("display esn")
        match = re.search(".*ESN of master:(.*)", serial)
        if match:
            self._update_serial(match.group(1), sysname)

    def _create_inventory(self, ssh_session_object, sysname):
        """
        Checking and creating/updating inventory from 'display elabel' command
        """
        inventory = self._check_elabel(ssh_session_object)
        for part in inventory:
            if not part["serial"]:
                continue
            inv_object = self.nb.dcim.inventory_items.filter(
                serial=part["serial"].strip()
            )
            manufacturer_strip = part["manufacturer"].strip()
            part["manufacturer"] = manufacturer_strip
            part["device"] = sysname
            if not self.nb.dcim.manufacturers.filter(name=manufacturer_strip):
                vendor_slug = re.sub(r" |-|\.", "_", manufacturer_strip)
                self.nb.dcim.manufacturers.create(
                    name=manufacturer_strip, slug=vendor_slug
                )
            upd_part = self._check_part(part, sysname)
            if not inv_object:
                self.nb.dcim.inventory_items.create(upd_part)
            else:
                if len(inv_object) > 1:
                    for o in inv_object[1:]:
                        o.delete()
                inv_obj_dict = {
                    "device": inv_object[0].device,
                    "manufacturer": inv_object[0].manufacturer,
                    "part_id": inv_object[0].part_id,
                    "description": inv_object[0].description,
                }
                for key, value in inv_obj_dict.items():
                    if part[key] != str(value):
                        inv_object[0].update(upd_part)
                        break

    def _check_part(self, part, sysname):
        upd_part = part.copy()
        # because length of description field is 100 characters
        if len(part["description"]) > 100:
            upd_description = re.sub(
                r"Assembling Components,| |\(|\)", "", part["description"]
            )[0:99]
            upd_part.update({"description": upd_description})
        upd_name = part["name"][0].strip("[]")
        upd_part.update(
            {
                "name": upd_name,
                "device": {"name": sysname},
                "manufacturer": {"name": part["manufacturer"]},
            }
        )
        if not upd_part["manufacturer"]["name"]:
            del upd_part["manufacturer"]
        return upd_part

    def _create_addresses_from_arp_cache(self, ssh_session_object, sysname):
        """
        Checking and creating ip addresses from arp cache.
        Sysname and arp interface will be in ip address description
        """
        regex = r"(?P<address>\d+(.\d+){3})\s+(\w+-\w+-\w+).*"
        description = "Added from arp cache of {}, interface {}"
        for intf in self.arp_interfaces:
            arp_out = ssh_session_object.send_command(f"disp arp interface {intf}")
            if "Error" in arp_out:
                raise ValueError(
                    "Not correct interface for display arp interface command"
                )
            arp_list = [match.group("address") for match in re.finditer(regex, arp_out)]
            mask = (
                "/"
                + str(
                    self.nb.ipam.ip_addresses.filter(device=sysname, interface=intf)[0]
                ).split("/")[1]
            )
            for addr in arp_list:
                address_with_mask = addr + mask
                if not self.nb.ipam.ip_addresses.filter(address=address_with_mask):
                    self.nb.ipam.ip_addresses.create(
                        {
                            "address": address_with_mask,
                            "description": description.format(sysname, intf),
                        }
                    )

    def _create_prefixes_ip_addresses(
        self, ip_addresses, sysname, current_mgmt_ip, ssh_session_object
    ):
        for addresses in ip_addresses:
            if addresses["name"] and addresses["address"]:
                self._check_cur_interface_addresses(
                    sysname, addresses["name"], addresses["address"]
                )
                cur_addr = addresses["address"][0]
                for addr in addresses["address"]:
                    network = self._check_network(addr)
                    self._create_prefix(network)
                    network_object = self.nb.ipam.prefixes.get(prefix=network)

                    if not self.nb.ipam.ip_addresses.filter(address=addr):
                        self.nb.ipam.ip_addresses.create(
                            {
                                "address": addr,
                                "interface": {
                                    "device": {"name": sysname},
                                    "name": addresses["name"],
                                },
                            }
                        )
                    address_object = self.nb.ipam.ip_addresses.filter(address=addr)[0]

                    description = self._check_cur_int(
                        addresses["name"], ssh_session_object
                    )

                    if not address_object.interface:
                        address_object.update(
                            {
                                "address": addr,
                                "interface": {
                                    "device": {"name": sysname},
                                    "name": addresses["name"],
                                },
                                "description": description,
                            }
                        )

                    else:
                        address_object_dict = {
                            address_object.interface.device.name: sysname,
                            address_object.interface.name: addresses["name"],
                            address_object.description: description,
                        }

                        for key, value in address_object_dict.items():
                            if not key == value:
                                address_object.update(
                                    {
                                        "address": addr,
                                        "interface": {
                                            "device": {"name": sysname},
                                            "name": addresses["name"],
                                        },
                                        "description": description,
                                    }
                                )
                                break

                    vrf = self._check_vrf_interfaces(
                        addresses["name"], ssh_session_object
                    )
                    # binding ip interface to vrf
                    if vrf and not address_object.vrf == vrf:
                        self._vrf_binding(vrf, network_object, address_object)
                    # mgmt ip address
                    # it can use for napalm_ce driver, for example
                    self._update_mgmt_ipv4(sysname, current_mgmt_ip, cur_addr)

    def _check_cur_interface_addresses(self, sysname, interface_name, addresses_list):
        """
        Delete ip address on ip interfaces if it's incorrect(not actual)
        """
        cur_addr_list = self.nb.ipam.ip_addresses.filter(
            device=sysname, interface=interface_name
        )
        if cur_addr_list:
            for cur_intf_address in cur_addr_list:
                if not str(cur_intf_address) in addresses_list:
                    cur_addr_obj = self.nb.ipam.ip_addresses.filter(
                        device=sysname,
                        interface=interface_name,
                        address=str(cur_intf_address),
                    )
                    for obj in cur_addr_obj:
                        obj.delete()

    def _create_prefix(self, network):
        if not "/32" in network and not self.nb.ipam.prefixes.filter(prefix=network):
            self.nb.ipam.prefixes.create({"prefix": network})

    def _vrf_binding(self, vrf, network_object, address_object):
        network_object.update({"vrf": {"name": vrf}})
        address_object.update({"vrf": {"name": vrf}})

    def _update_mgmt_ipv4(self, sysname, current_mgmt_ip, current_list_ip):
        """
        Binding ip address of the interface as primary ipv4.
        Method checks your :ip: or :ip_list: also

        """
        mgmt_ip = self.nb.dcim.devices.get(name=sysname)
        if not mgmt_ip.primary_ip4 or current_mgmt_ip not in mgmt_ip.primary_ip4:
            if current_mgmt_ip in current_list_ip:
                mgmt_ip.update({"primary_ip4": {"address": current_list_ip}})

    def _get_create(self, points):
        """
        Universal method for requesting and creation something
        """
        for key, value in points.items():
            if not key.get(**value[0]):
                key.create(value[1])

    def _create_interfaces(self, interfaces, interfaces_vars):
        for intf in interfaces:
            # intf.update({'device': {'name': sysname}})
            for key, value in interfaces_vars.items():
                for intf_type in key:
                    if intf["name"].startswith(intf_type):
                        intf.update({"type": value})
            self.nb.dcim.interfaces.create(intf)

    def _update_interfaces(self, sysname, interfaces, interfaces_vars):
        """
        Delete/update/create interfaces
        """
        interfaces_list = []
        netbox_interfaces = self.nb.dcim.interfaces.filter(device=sysname)
        if netbox_interfaces:
            for intf in interfaces:
                interfaces_list.append(intf["name"])
            for intf_object in netbox_interfaces:
                if not str(intf_object) in interfaces_list:
                    intf_object.delete()
                else:
                    intf_object_dict = dict(intf_object)
                    index = interfaces_list.index(str(intf_object))
                    for key, value in interfaces[index].items():
                        if value != intf_object_dict[key]:
                            intf_object.update({key: value})
            self._repeat_interfaces_check(sysname, interfaces, interfaces_vars)
        else:
            self._create_interfaces(interfaces, interfaces_vars)

    def _repeat_interfaces_check(self, sysname, interfaces, interfaces_vars):
        netbox_interfaces = self.nb.dcim.interfaces.filter(device=sysname)
        if netbox_interfaces:
            str_netbox_interfaces = [str(i) for i in netbox_interfaces]
            # str_netbox_interfaces = str(netbox_interfaces)
            for intf in interfaces:
                if not intf["name"] in str_netbox_interfaces:
                    self._create_interfaces([intf], interfaces_vars)
        else:
            self._create_interfaces(interfaces, interfaces_vars)

    def _create_device(self, device_vars, points, sysname, interfaces, interfaces_vars):
        key, value = list(device_vars.items())[0]
        if not key.get(**value[0]):
            self._get_create(points)
            key.create(value[1])
            self._create_interfaces(interfaces, interfaces_vars)

    def _update_device(
        self, device_vars, points, model, site, sysname, interfaces, interfaces_vars
    ):
        """
        Update device parameters if they don't  match default
        """
        key, value = list(device_vars.items())[0]
        if key.get(**value[0]):
            self._get_create(points)
            device_object = self.nb.dcim.devices.get(**value[0])
            update_params = {
                device_object.device_type.manufacturer.name: (
                    "Huawei Technologies",
                    {"manufacturer": {"name": "Huawei Technologies"}},
                ),
                device_object.device_type.model: (
                    model,
                    {"device_type": {"model": model}},
                ),
                # device_object.site.slug: (site, {'site': {'slug': site}}),
            }
            for key, value in update_params.items():
                if not key == value[0]:
                    device_object.update(value[1])
            if (
                not device_object.platform
                or not device_object.platform.name == "Huawei VRP"
            ):
                device_object.update({"platform": {"name": "Huawei VRP"}})

            self._update_interfaces(sysname, interfaces, interfaces_vars)

    def _check_model(self, ssh_session_object):
        return ssh_session_object.send_command("disp dev", use_textfsm=True)

    def _check_interfaces(self, sysname, ssh_session_object):
        params = ["mtu", "mac_address"]
        interfaces = ssh_session_object.send_command("disp interface", use_textfsm=True)
        for intf in interfaces:
            intf.update({"device": {"name": sysname}})
            for param in params:
                if not intf[param]:
                    del intf[param]
        return interfaces

    def _check_ip_addresses(self, ssh_session_object):
        return ssh_session_object.send_command("disp ip int", use_textfsm=True)

    def _check_elabel(self, ssh_session_object):
        """
        Output parsing.
        It works in dialogue mode also.
        As an option, "Warning: It may take a long time to excute this command. Continue? [Y/N]:"
        Netmiko example for dialogue - https://github.com/ktbyers/netmiko/blob/develop/examples/use_cases/case5_prompting/send_command_prompting.py
        """
        output = ssh_session_object.send_command_timing(
            "display elabel", delay_factor=3, use_textfsm=True
        )
        if "Continue" in output:
            output = ssh_session_object.send_command_timing(
                "Y", delay_factor=3, use_textfsm=True
            )
        return output

    def _check_cur_int(self, interface, ssh_session_object):
        parse_cur_int = ssh_session_object.send_command(
            "disp cur int", use_textfsm=True
        )
        for value in parse_cur_int:
            if interface == value["interface"]:
                return value["description"]
                # break

    def _create_vrfs(self, ssh_session_object):
        vrf_dict = {}
        vrfs = self.nb.ipam.vrfs.all()
        for v in vrfs:
            vrf_dict[v.name] = v.rd
        parse_vrf = ssh_session_object.send_command("di ip v", use_textfsm=True)
        if isinstance(parse_vrf, list):
            for item in parse_vrf:
                if item["rd"]:
                    if (
                        item["name"] in vrf_dict
                        and not vrf_dict[item["name"]] == item["rd"]
                    ):
                        try:
                            self._update_vrf(item["name"], item["rd"])
                        except RequestError:
                            continue
                    elif not (item["name"], item["rd"]) in vrf_dict.items():
                        try:
                            self._create_vrf(item)
                        except RequestError:
                            continue
                else:
                    if item["name"] in vrf_dict:
                        continue
                    else:
                        try:
                            self._create_vrf({"name": item["name"]})
                        except RequestError:
                            continue
                # return True

    def _create_vrf(self, vrf_dict):
        self.nb.ipam.vrfs.create(vrf_dict)

    def _update_vrf(self, vrf_name, rd):
        vrf = self.nb.ipam.vrfs.get(name=vrf_name)
        vrf.update({"rd": rd})

    def _check_vrf_interfaces(self, interface, ssh_session_object):
        vrf_interfaces = ssh_session_object.send_command("di ip v in", use_textfsm=True)
        if vrf_interfaces and isinstance(vrf_interfaces, list):
            for intf in vrf_interfaces:
                if interface in intf["interface"]:
                    vrf = intf["name"]
                    return vrf
                    # break

    def _check_network(self, ip_address):
        ip_interface = ipaddress.ip_interface(ip_address)
        return str(ip_interface.network)

    def _check_net_textfsm(self):
        """
        Adding a system variable for netmiko textfsm preparsing.
        As an example - https://pynet.twb-tech.com/blog/automation/netmiko-textfsm.html
        """
        template_path = os.path.join(os.getcwd(), "templates")
        if "NET_TEXTFSM" not in os.environ:
            os.environ["NET_TEXTFSM"] = template_path

    def _task_queue(self, task, iterator, concurrency=3, on_fail=lambda _: None):
        """
        Method controls numbers of working threads and logs it.
        Current number of working threads = concurrency(:max_workers:) always.
        """

        def _submit():
            try:
                obj = next(iterator)
            except StopIteration:
                return
            if result.cancelled():
                return

            stats["delayed"] += 1
            future = executor.submit(task, obj, obj["ip"])
            future.ip = obj["ip"]
            future.obj = obj
            # check future status and call '_task_done' method with future
            future.add_done_callback(_task_done)

        def _task_done(future):
            # log completed future
            if future.done():
                logging.info(
                    msg_info_thread_done.format(datetime.now().time(), future.ip)
                )

            with io_lock:
                # create new future because previous one is completed
                _submit()
                stats["delayed"] -= 1
                stats["done"] += 1

            if future.exception():
                on_fail(future.exception(), future.obj)
            # when all futures are completed, set status for result(future)
            # and shutdown executor
            if stats["delayed"] == 0:
                result.set_result(stats)

        def _cleanup(_):
            with io_lock:
                executor.shutdown(wait=False)

        msg_info_thread_done = "< --- {} Thread done for {}"

        io_lock = RLock()
        executor = ThreadPoolExecutor(max_workers=concurrency)
        result = Future()
        result.stats = stats = {"done": 0, "delayed": 0}
        result.add_done_callback(_cleanup)
        #        with ThreadPoolExecutor(max_workers = concurrency) as executor:
        #            future_list = [executor.submit(task, device, device['ip']) for
        #                           device in iterator]

        with io_lock:
            for _ in range(concurrency):
                _submit()
        return result
