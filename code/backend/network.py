from scapy.all import *
import scapy.layers
import scapy.layers.l2
import math
import ipaddress

from info import my_info as api_info

class dhcp_class():

    def __init__(self):
        """
        An object which handles dhcp function and saves (relevant/interestng) dhcp data
        """
        self._discover = None    # type: scapy.layers.l2.Ether
        self._offers = []          # type: list[scapy.layers.l2.Ether]      # list because there could be more offers, the first offer will be accepted
        self.offerCounter = len(self._offers)                             # to see how many offers 
        self._request = None     # type: scapy.layers.l2.Ether
        self._ack = None           # type: scapy.layers.l2.Ether
        self.new_ip = None      # type: str
        self.gateway = None     # type: str
        # self.cidr = None        # type: int   # deprecated by netmask
        self.netmask = None     # type: str     
        self.options = []       # type: list[(str, str)]     # dhcp offer or ack could have different options --> this list always contains the newest option list

    def build_dhcp_discover(self):
        """
        This function returns the built ethernet frame of the dhcp_discover paacket
        :return: None
        """
        device_mac = api_info.get_nicInfo()[1]
        eth_frame = scapy.layers.l2.Ether(type=2048, dst="ff:ff:ff:ff:ff:ff", src=device_mac)
        ip_packet = scapy.layers.inet.IP(src="0.0.0.0", dst="255.255.255.255", proto="udp")
        proto_segment = scapy.layers.inet.UDP(sport=68, dport=67)
        bootp_message = scapy.layers.dhcp.BOOTP(op=1, chaddr=device_mac)
        dhcp_discover = scapy.layers.dhcp.DHCP(options=[("message-type", "discover"), ("end")])     # adding ("chaddr", device_mac) to list, does not change send chaddr in dhcp_offer
        eth_dhcp_discover = eth_frame/ip_packet/proto_segment/bootp_message/dhcp_discover
        # eth_dhcp_discover.show()
        self._discover = eth_dhcp_discover

    def build_dhcp_request(self):
        """
        This function parses the turned over dhcp_offer to build and returns the dhcp_request.

        :param dhcp_offer: dhcp_offer to which the response is to be generated
        :type dhcp_offer: scapy.layers.l2.Ether
        :returns: None
        """
        device_mac = api_info.get_nicInfo()[1]
        eth_frame = scapy.layers.l2.Ether(type=2048, dst="ff:ff:ff:ff:ff:ff", src=device_mac)
        ip_packet = scapy.layers.inet.IP(src="0.0.0.0", dst="255.255.255.255", proto="udp")
        proto_segment = scapy.layers.inet.UDP(sport=68, dport=67)
        bootp_message = scapy.layers.dhcp.BOOTP(op=1, chaddr=device_mac)
        # self.new_ip has been set after dhcp discover was sent, in self.send_packet()
        dhcp_request = scapy.layers.dhcp.DHCP(options=[("message-type", "request"), ("requested_addr", self.new_ip), ("end")])
        eth_dhcp_request = eth_frame/ip_packet/proto_segment/bootp_message/dhcp_request

        self._request = eth_dhcp_request

    def write_dhcp_info(self, replys):
        """
        Parses the dhcp packet and writes the additional information into the object. 

        :param replys: list of the bootreplys (either OFFER or ACK)
        :type replys: list[scapy.layers.l2.Ether]
        """
        # checking for empty response list
        if replys == None:
            raise AssertionError
        
        # replys[0].show()
        # print(replys[0]["DHCP"].options[0])
        
        # only the first response is considered (either the first OFFER ... fifo OR there is only 1 response ... the ACK )
        dhcp_reply = replys[0]

        # determining THAT either offer or ack is the packet in question
        if dhcp_reply["DHCP"].options[0][1] == 2:            # options[0] --> first object in list of options (beeing "message-type"); options[0][1] --> value of "message-type" ... can be read in rfc2132
            for offer in replys:
                clean_offer = self.clean_dhcp_packet(offer)
                self._offers.append(clean_offer)
            self.offerCounter = len(self._offers)
        elif (dhcp_reply["DHCP"].options[0][1] == 5) and len(replys) == 1:       # 5 is an ack 
            clean_ack = self.clean_dhcp_packet(dhcp_reply)
            self._ack = clean_ack
        else:
            print("If this code path is triggert, the server did neither send an dhcp offer nor a dhcp ack ... therefore something went wrong :(")
            raise ValueError
        
        # setting interesting values
        self.new_ip = dhcp_reply["BOOTP"].yiaddr        
        for option_index in range(len(dhcp_reply["DHCP"].options)):
            if dhcp_reply["DHCP"].options[option_index][0] == "subnet_mask":
                self.netmask = dhcp_reply["DHCP"].options[option_index][1]
                continue
            if dhcp_reply["DHCP"].options[option_index][0] == "router":
                self.gateway = dhcp_reply["DHCP"].options[option_index][1]
                continue
        # setting the options
        self.options = dhcp_reply["DHCP"].options

    def clean_dhcp_packet(self, pkt_in):
        """
        removes "pad" entries from dhcp options. -> this function can be extendet as necessary

        :param pkt_in: to be cleaned dhcp packet
        :type pkt_in: scapy.l2.Ether
        
        :returns: cleaned dhcp packet
        :rtype: scapy.l2.Ether
        """
        while "pad" in pkt_in["DHCP"].options:
            pkt_in["DHCP"].options.remove("pad")
        return pkt_in

    def send_packet(self, packet, dhcp=True):
        """
        This function sends a packet (bootrequest: dhcpdiscover and dhcprequest), and waits for responses (bootreply) and returns these.

        :packet: the dhcp packet to be send 
        :type packet: scapy.layers.l2.Ether
        :returns:  list of replys to the requests ... there could be more than one reponse to the sent request
        :rtype: scapy.layers.l2.Ether
        """
        device_name = api_info.get_nicInfo()[0]
        conf.checkIPaddr = False            # setting this conf is very important ... if not set, scapy can not match the dhcp offer to my sent dhcp discover
        ans, unans =srp(packet, iface=device_name, multi=True, timeout=api_info.get_timeout())
        
        answers = []                        # creating a list for answers, as there could be multiple responses
        for send_recive in ans:             # itterating through all the responses
            answers.append(send_recive[1])  # answers are saved as send_recieve list ... first element beeing the request, second the response --> the one we are interested in
        
        # print(type(ans))               
        # print(type(ans[0]))
        # bootreply = ans[0][1]
        if dhcp:
            self.write_dhcp_info(answers)
        # bootreply.show()
        # print(bootreply["IP"].proto)

        return answers

    # def subent_to_cidr(self, mask):
    #     """
    #     Converts subnet mask to cidr. DHCP provides subnet mask, to bind ip however cidr notation is needed.

    #     :param mask: the subnet mask to be converted into cidr
    #     :type mask: str
    #     :returns: cidr notation of subnet mask
    #     :rtype: int
    #     """
        
    #     mask_bytes = mask.split(".")
    #     if len(mask_bytes) != 4:
    #         raise ValueError

    #     bin_bytes = [0, 0, 0, 0]
    #     for byte in range(len(mask_bytes)):
    #         bin_byte = bin(int(mask_bytes[byte]))[2:]
    #         bin_bytes[byte] = bin_byte.zfill(8)         # makes sure it has a length of 32 bits ... and sets up catching wrong subnetmasks

    #     bin_bits = "".join(bin_bytes)
    #     last_bit_zero = False
    #     cidr = 0
    #     for bit_index in range(32):                     # length of subnet mask as bits ... ensured by zfill(8) eralier # could also use range(len(bin_bytes)) ... 32 is more expressif
    #         if bin_bits[bit_index] == "1":
    #             if last_bit_zero == False:
    #                 cidr = cidr + 1
    #             else:
    #                 raise ValueError                    # this means the last bit was a 0 and the current bit is a 1 ... which is an impossible constellation in a subnetmask
    #         else:
    #             last_bit_zero = True

    #     return cidr

    def bind_new_ip(self):
        """
        Binds the new IP to the interface. 
        :return: void
        """
        self.release_and_flush_old_ip()     # bevor new ip can be bound old ip needs to be removed
        # # cidr = self.cidr      # deprecated ... found a library that retruns the exact notation needed for binding thee ip address
        # if (new_ip or cidr) == None:
        #     raise ValueError
        # subprocess.run(f"ip addr add {new_ip}/{cidr} dev {api_info.get_nicInfo()[0]}", shell=True, check=True)
        
        ip_cidr = ipaddress.ip_interface(self.new_ip + "/" + self.netmask)
        #print(binding_ip)
        subprocess.run(f"ip addr add {ip_cidr} dev {api_info.get_nicInfo()[0]}", shell=True, check=True)
        subprocess.run(f"ip route add default via {self.gateway} dev {api_info.get_nicInfo()[0]}", shell=True, check=True)
        # subprocess.run(f"ip route add {self.cidr} dev {api_info.get_nicInfo()[0]}")

    def arp_ping(self):
        """
        Bevor a DHCP DECLINE can be acceped the client needs to check if the suggested ip address is already taken. 
        As this program is not a dhcp client only states that the IP address already is taken.

        :returns: if ip is taken -> TRUE ip IS taken, FALSE ip IS NOT taken
        :rtype: bool
        """
        ipIsTaken = True            # better to not take an ip that might or might not be taken, rather than having the same ip as some other devive
        if self.new_ip == None:
            print("No IP Address to arp test")
        arp = scapy.layers.l2.Ether(dst="ff:ff:ff:ff:ff:ff")/scapy.layers.l2.ARP(pdst=self.new_ip, hwsrc=api_info.get_nicInfo()[1])
        arprl = self.send_packet(arp, dhcp=False)       # arprl: arp response list
        # if there are no responses to the arp request that means the ip is likly NOT taken
        if len(arprl) == 0:
            ipIsTaken = False
        # arps op field is used as an indicator whether or not a ip currently is in use ... if someone answers 
        # ... however it is worth mentioning this is not secured in any way against spoofing attacks 
        elif len(arprl) == 1:
            if arprl[0]["ARP"].op == "is-at":
                ipIsTaken = True
        else:    
            print("OWKAY ... something is wrong, multiple answeser for 1 arp request")
            print(len(arprl))
            for arpr in arprl:
                if arpr["ARP"].op == "is-at":   
                    ipIsTaken = True
                    print("arp: ip taken")
        return ipIsTaken

    def release_and_flush_old_ip(self):
        """
        Remove all IPs from an interface.
        :return: void
        """
        release = self.build_dhcp_release()
        self.send_packet(release, dhcp=False)
        subprocess.run(f"ip addr flush dev {api_info.get_nicInfo()[0]}", shell=True, check=True)

    def build_dhcp_release(self):
        """
        This function builds a DHCp Release, which is nessecary to no starve the dhcp server of IP addresses.
        DHCP Release is not saves into DHCP as it deprecates the previous DHCP information und therefor there would be no value in saving it. ---> so gets returned

        :returns: the ethernet packet of the DHCP Release
        :rtype: scapy.layers.l2.Ether
        """
        
        device_mac = api_info.get_nicInfo()[1]
        old_ip = self.new_ip
        eth_frame = scapy.layers.l2.Ether(type=2048, dst="ff:ff:ff:ff:ff:ff", src=device_mac)
        ip_packet = scapy.layers.inet.IP(src="0.0.0.0", dst="255.255.255.255", proto="udp")
        proto_segment = scapy.layers.inet.UDP(sport=68, dport=67)
        bootp_message = scapy.layers.dhcp.BOOTP(op=1, chaddr=device_mac, ciaddr=old_ip)
        dhcp_release = scapy.layers.dhcp.DHCP(options=[("message-type", 7), ("end")])
        eth_dhcp_release = eth_frame/ip_packet/proto_segment/bootp_message/dhcp_release
        return eth_dhcp_release


def test_carrier():
    """
    Test whether or not device is connected to routing device.
    Utelising: ethtool

    :returns: TRUE: if carrier signal is present; FALSE: no carrier signal present
    :rtype: bool
    """
    device_name = api_info.get_nicInfo()[0]
    ethtool = subprocess.run(f"ethtool {device_name} | grep -i 'link detected:'", shell=True, text=True, capture_output=True)
    if ethtool.returncode != 0:
        print("ethtool went wrong")
        raise AssertionError
    phy_carrier = ethtool.stdout.split(":")[1].strip()
    if phy_carrier == "yes":
        return True
    elif phy_carrier == "no":
        return False
    else:
        print("ethtool output could not be parsed")
        raise AssertionError

def test_portal():
    """

    """
    # for now unit there is a real portal test
    return True

def test_uplink():
        """
        This tests whether clients can reach the internet by sending a curl to clouldflare. 
            Cloudflare or rather cloudflares IPs via https so the certificate is checkt to definitvly know there is an uplink.
            Alternative would be cloudlfare is down.
        
        :returns: whether or not there is a uplink
        :rtype: bool
        """
        clflr1 = subprocess.run(f"curl --connection-timeout {api_info.get_timeout()} https://1.1.1.1",shell=True, text=True, capture_output=True)
        clflr2 = subprocess.run(f"curl --connection-timeout {api_info.get_timeout()} https://9.9.9.9",shell=True, text=True, capture_output=True)
        if clflr1.returncode != 0 and clflr2.returncode != 0:
            return False
        else:
            return True

def dummy_test_uplink():
    return True

def test_isp():
        """
        After uplink has been tested. Determins global IP and ISP.
        Utelising: whois

        :rtype: (str, str)
        :returns: global IP , ISP 
        """
        glob_ip = subprocess.run("curl https://ipinfo.io/ip", shell=True, text=True, capture_output=True)
        if glob_ip.returncode != 0:
            print("getting IP -> failed")
            raise AssertionError
        # hier muss irwie noch die globale IP gespeichert werden
        isp = subprocess.run(f"whois {glob_ip.stdout} | grep 'descr'", shell=True, text=True, capture_output=True)
        if isp.returncode != 0:
            print("whois <IP> -> failed")
            raise AssertionError
        if "RIPE" in isp.stdout:
            isp = subprocess.run(f"whois -h whois.ripe.net {glob_ip.stdout} | grep 'descr'", shell=True, text=True, capture_output=True)
        if isp.returncode != 0:
            print("whois -h whois.ripe.net <IP> -> failed")
            raise AssertionError
        isp = subprocess.run(f"whois -h whois.ripe.net {glob_ip.stdout} | grep 'descr'", shell=True, text=True, capture_output=True)
        isp_name = isp.stdout.split(":")[1].strip()
        # or mabye setting it to some global variables ... we'll see
        return (glob_ip.stdout, isp_name)

