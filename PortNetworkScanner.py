from scapy.all import ARP, Ether, srp
import socket

#function scans the local network for live hosts using ARP
def scan_network(network):

    print(f"Scanning network {network} for live hosts...")
    
    arp_request = ARP(pdst=network)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = srp(arp_request_broadcast, timeout=2, verbose=0)[0]

    live_hosts = []
    for sent, received in answered_list:
        live_hosts.append(received.psrc)
    return live_hosts

#function scans open ports using socket
def scan_ports(ip, ports):

    open_ports = []
    print(f"Scanning {ip} for open ports...")
    
    for port in ports:
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        
        result = sock.connect_ex((ip, port))
        
        if result == 0:
            open_ports.append(port)
        sock.close()

    return open_ports



if __name__ == "__main__":

    #network range to scan
    network_range = "192.168.1.0/24"
    live_hosts = scan_network(network_range)

    #common ports to scan on live host
    ports_to_scan = [21, 22, 23, 80, 443, 8080] 

    for host in live_hosts:

        open_ports = scan_ports(host, ports_to_scan)
        
        if open_ports:
            print(f"Host {host} has open ports: {open_ports}")
        
        else:
            print(f"No open ports found on {host}")
