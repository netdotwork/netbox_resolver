# for debugging with pdb
if __name__ == "__main__":
    device_params = {
    "netbox": "http://netbox_domain_name_or_ip/",
    "token": "netbox_token",
    "device_type": "huawei",
    "ip": "",
    "username": "user",
    "password": "password",
    "inventory": True,
    "port": 22,
    }
    from vendor_selector import VendorSelector
    o = VendorSelector(**device_params)
    o.send_ip()
