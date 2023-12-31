import scapy.all as scapy
import argparse

def get_mac(ip):
    arp_req = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_packet = broadcast/arp_req
    answered_list = scapy.srp(arp_packet, timeout=1, verbose=False)[0]
    print(answered_list)
    return answered_list[0][1].hwsrc

def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target",
                        help="Target IP/IP Range")
    options = parser.parse_args()
    return options
def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]    
    clients_list = []
    for element in answered_list:
        client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        clients_list.append(client_dict)
    return clients_list
def print_result(results_list):
    print("IP\t\t\tMAC Address")
    print("----------------------------------------------------")
    for client in results_list:
        print(client["ip"] + "\t\t" + client["mac"])
        
if __name__ == "__main__":
    #print(get_mac("192.168.50.1"))
    options = get_arguments()
    scan_result = scan(options.target)
    print_result(scan_result)


