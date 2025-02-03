from scapy.all import *
import scapy.layers
import scapy.layers
import scapy.layers.l2

from scan import scan_settings


class dhcp():

    def __init__(self):
        self.offer = []
        self.offerCountee = len(self.offer)


def build_dhcp_discover():
    """
    This function returns the built ethernet frame of the dhcp_discover paacket
    """
    device_mac = scan_settings.get_nicInfo()[1]
    eth_frame = scapy.layers.l2.Ether(type=2048, dst="ff:ff:ff:ff:ff:ff", src=device_mac)
    ip_packet = scapy.layers.inet.IP(src="0.0.0.0", dst="255.255.255.255", proto="udp")
    proto_segment = scapy.layers.inet.UDP(sport=68, dport=67)
    bootp_message = scapy.layers.dhcp.BOOTP(op=1, chaddr=device_mac)
    dhcp_discover = scapy.layers.dhcp.DHCP(options=[("message-type", "discover"), ("end")])     # adding ("chaddr", device_mac) to list, does not change send chaddr in dhcp_offer
    eth_dhcp_discover = eth_frame/ip_packet/proto_segment/bootp_message/dhcp_discover
    return eth_dhcp_discover


def get_dhcp_offer():
    """
    This function send the dhcp_discover packet and waits for dhcp offer packet (the response to dhcp discover) to return and returns said offer.
    """
    device_name=scan_settings.get_nicInfo()[0]
    discover = build_dhcp_discover()
    conf.checkIPaddr = False                # setting this conf is very important ... if not set, scapy can not match the dhcp offer to my sent dhcp discover
    ans, unans =srp(discover, iface=device_name, multi=True, timeout=2)
    ans.show()
    # print(type(ans))
    # print(type(ans[0]))
    dhcp_offer = ans[0][1]
    dhcp_offer.show()
    # print(dhcp_offer[IP].proto)     # this would normally call a waring as it does not recognize the layer of the packet i.e. [IP] ... but it does work     # type: ignore  
    return dhcp_offer

def build_dhcp_request(dhcp_offer):
    """
    This function parses the turned over dhcp_offer to build and returns the dhcp_request.
    """
    device_mac = scan_settings.get_nicInfo()[1]
    eth_frame = scapy.layers.l2.Ether(type=2048, dst="ff:ff:ff:ff:ff:ff", src=device_mac)
    ip_packet = scapy.layers.inet.IP(src="0.0.0.0", dst="255.255.255.255", proto="udp")
    proto_segment = scapy.layers.inet.UDP(sport=68, dport=67)

    # print(dhcp_offer[BOOTP].summery())     # type: ignore
    # print(dhcp_offer[DHCP].summery())     # type: ignore
    assigned_ip = dhcp_offer[BOOTP].yiaddr    # type: ignore
    print(f"assigned ip: {assigned_ip}")

    bootp_message = scapy.layers.dhcp.BOOTP(op=1, chaddr=device_mac, ciaddr=assigned_ip)
    dhcp_request = scapy.layers.dhcp.DHCP(options=[("message-type", "request"), ("end")])
    eth_dhcp_request = eth_frame/ip_packet/proto_segment/bootp_message/dhcp_request
    return eth_dhcp_request

def send_dhcp_request(request):
    """
    This function sends the dhcp_request and waits for confimation in form of dhcp_ack.
    """
    device_name=scan_settings.get_nicInfo()[0]
    conf.checkIPaddr = False                # setting this conf is very important ... if not set, scapy can not match the dhcp offer to my sent dhcp discover
    ans, unans =srp(request, iface=device_name, multi=True, timeout=2)
    ans.show()
    # print(type(ans))
    # print(type(ans[0]))
    dhcp_ack = ans[0][1]
    dhcp_ack.show()
    # print(dhcp_offer[IP].proto)     # this would normally call a waring as it does not recognize the layer of the packet i.e. [IP] ... but it does work     # type: ignore  
    return dhcp_ack



offer = get_dhcp_offer()
request = build_dhcp_request(offer)
ack = send_dhcp_request(request)
new_ip = ack[BOOTP].ciaddr   # type: ignore


subprocess.run(f"ip addr add {new_ip}/24 dev {scan_settings.get_nicInfo()[0]}", shell=True, check=True)
# subprocess.run(f"ip link set {scan_settings.get_nicInfo[0]}up", shell=True, check=True)
