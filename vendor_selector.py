from huawei.huawei import HuaweiIpam


platforms = {
    "huawei": HuaweiIpam,
}

platforms_str = "\n".join(list(platforms.keys()))


def VendorSelector(*args, **kwargs):
    """Selecting vendor class based on device_type. The same as netmiko ConnectHandler"""
    if kwargs["device_type"] not in platforms:
        raise ValueError(
            "Unfortunately it's not supported device_type yet. "
            f"\nSupported platforms:\n{platforms_str}"
        )
    IpamClass = platforms[kwargs["device_type"]]
    return IpamClass(*args, **kwargs)
