from netifaces import interfaces, ifaddresses, AF_INET


def show_ips():
    my_ips = {}
    for iface_name in interfaces():
        addresses = [i['addr'] for i in ifaddresses(iface_name).setdefault(AF_INET, [{'addr': 'No IP addr'}])]
        if "No IP addr" not in addresses:
            my_ips[iface_name] = ', '.join(addresses)
    print("\nIP addresses on this computer:")
    print("\n".join(": ".join(_) for _ in sorted(my_ips.items())))
