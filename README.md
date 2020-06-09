## Netbox_resolver

Netbox_resolver is an autoIPAM/DCIM tool for [NetBox](https://github.com/netbox-community/netbox)

You can add new data, check/correct previously added data in the NetBox database and automate this process using the scheduler.

Netbox_resolver will collect as much information as possible from devices and add it to netbox (if there is no device, it will create it):
- Site
- Device Type
- Role (Device Role)
- Manufacturer
- Platform
- Serial
- VRF (binds RD)
- Prefixes and IP Addresses (binds to the VRF, to the interface)
- Primary IPv4
- Interfaces (for each interface, inserts the fields: Device, Name, Type, MTU, MAC Address, Description, IP Address (+sub addresses)
- Inventory (with the option inventory: True)

Netbox_resolver will fix a mismatch in the netbox database based on information from devices:
- Manufacturer
- Device Type
- Serial
- Interfaces (removes those that are not present on the device, adds the latest ones)
- VRF (checks RD compliance)
- IP Addresses (will check the parameters and binding to the interface, delete or update, if necessary)
- Inventory (with the option inventory: True, will check the Inventory for device)

## Platforms

**Supported platforms:**
- Huawei VRP

_ _ _

For Huawei VRP will be created and used by default for new devices:
- Device roles: Network device
- Manufacturers: Huawei Technologies
- Platforms: Huawei VRP

For Huawei VRP, TextFSM parses the output of the following commands:
- display elabel
- display arp all
- display ip vpn-instance interface
- display current-configuration interface
- display device
- display interface
- display esn
- display ip interface brief
- display ip interface
- display ip vpn-instance

For Huawei VRP, parameters such as Site(site), Device Type(model), and Name(sysname) are defined in the `def _create_all()` service method. Change them if necessary.

_ _ _

## Usage

Requires `Python 3.7+`

`pip install pynetbox`

`pip install netmiko`


**Netbox_resolver has only 2 methods:**
- `def send_ip(): for single device`
- `def send_ip_list(): for many devices`

Netbox_resolver has the same syntax as netmiko.

**You can run netbox_resolver for a single device:**

```python
device_params = {
"netbox": "http://netbox_domain_name_or_ip/",
"token": "netbox_token",
"device_type": "huawei",
"ip": "10.0.0.1",
"username": "user",
"password": "password",
}

from vendor_selector import VendorSelector

o = VendorSelector(**device_params)

o.send_ip()
```


**You can run netbox_resolver for n-th number of devices at the same time:**


```python
devices_params = {
"netbox": "http://netbox_domain_name_or_ip/",
"token": "netbox_token",
"device_type": "huawei",
"ip_list": ["10.1,2,3-5.1.1,2,3,4-10", "10.1.0.0/24"],
"threads": True,
"max_workers": 2,
"username": "user",
"password": "password",
}

from vendor_selector import VendorSelector

o = VendorSelector(**devices_params)

o.send_ip_list()
```
`threads` and `max_workers` are optional arguments

For `def send_ip_list()`:
- if you use incorrect netmiko connection arguments and errors `NetmikoTimeoutException`, `NetMikoAuthenticationException` occur, the method switches to the next device in the queue and sends the corresponding log to the output stream after the timeout expires.
- if you use `threads` and `max_workers`, you can press Ctrl+C for `KeyboardInterrupt`

## Netmiko, Pynetbox, TextFSM

Netbox_resolver is a wrapper on netmiko, so you can use all the arguments available in your version of netmiko.

Netbox_resolver uses the following modules:
- [Netmiko](https://github.com/ktbyers/netmiko)
- [Pynetbox](https://github.com/digitalocean/pynetbox) - Python API client library for NetBox
- [TextFSM](https://github.com/google/textfsm) - text output parsing
- Concurrent.futures, threading - works with threads
- Logging, time - logs working with threads

## Optional arguments

The following arguments are optional and described in `nb_ipam_resolver.py`:
- threads
- max_workers
- arp
- arp_interfaces
- inventory

## Scheduler

You can make the process regular by adding netbox_resolver to the scheduler, and as a result, automate the routine process of keeping IPAM/DCIM up to date.

### Protection from sysname changing

If you work with the scheduler and decide to change device sysname after it was added to the NetBox database, this can create a lil problem... Script will try to create a new device with new sysname. So it is better to add protection - in this case, script will not do anything until you match the device sysname and site, sysname in the NetBox database. In short, if you change sysname on device, you need to change device name and site in NetBox, otherwise this function returns nothing.

Please, check `huawei.py` and delete or comment block of code between `Protection from sysname changing` and `End of protection from sysname changing` if you don't need it.

## pdb

For script debugging you can add your parameters (for single device) in `pdb_test.py` and start pdb like `python -m pdb pdb_test.py` in your virtual environment.