from scapy.all import *
import scapy.layers
import scapy.layers
import scapy.layers
import scapy.layers.l2
import math

from backend.hwinfo import my_hw_info



class dhcp():

    def __init__(self):
        """
        An object which handles dhcp function and saves (relevant/interestng) dhcp data
        """
        self.discover = None    # type: scapy.layers.l2.Ether
        self.offers = []          # type: list[scapy.layers.l2.Ether]      # list because there could be more offers, the first offer will be accepted
        self.offerCounter = len(self.offers)                             # to see how many offers 
        self.request = None     # type: scapy.layers.l2.Ether
        self.ack = None           # type: scapy.layers.l2.Ether
        self.new_ip = None      # type: str
        self.cidr = None        # type: int
        self.options = []       # type: list[str]     # dhcp offer or ack could have different options --> this list always contains the newest option list


    def build_dhcp_discover(self):
        """
        This function returns the built ethernet frame of the dhcp_discover paacket
        :return: None
        """
        device_mac = my_hw_info.get_nicInfo()[1]
        eth_frame = scapy.layers.l2.Ether(type=2048, dst="ff:ff:ff:ff:ff:ff", src=device_mac)
        ip_packet = scapy.layers.inet.IP(src="0.0.0.0", dst="255.255.255.255", proto="udp")
        proto_segment = scapy.layers.inet.UDP(sport=68, dport=67)
        bootp_message = scapy.layers.dhcp.BOOTP(op=1, chaddr=device_mac)
        dhcp_discover = scapy.layers.dhcp.DHCP(options=[("message-type", "discover"), ("end")])     # adding ("chaddr", device_mac) to list, does not change send chaddr in dhcp_offer
        eth_dhcp_discover = eth_frame/ip_packet/proto_segment/bootp_message/dhcp_discover
        self.discover = eth_dhcp_discover


    def build_dhcp_request(self):
        """
        This function parses the turned over dhcp_offer to build and returns the dhcp_request.

        :param dhcp_offer: dhcp_offer to which the response shall be generated
        :type dhcp_offer: scapy.layers.l2.Ether
        :return: None
        """
        device_mac = my_hw_info.get_nicInfo()[1]
        eth_frame = scapy.layers.l2.Ether(type=2048, dst="ff:ff:ff:ff:ff:ff", src=device_mac)
        ip_packet = scapy.layers.inet.IP(src="0.0.0.0", dst="255.255.255.255", proto="udp")
        proto_segment = scapy.layers.inet.UDP(sport=68, dport=67)

        # print(dhcp_offer[BOOTP].summery())
        # print(dhcp_offer[DHCP].summery())
        # dhcp_offer.show()
        assigned_ip = self.new_ip
        # print(f"assigned ip: {assigned_ip}")

        bootp_message = scapy.layers.dhcp.BOOTP(op=1, chaddr=device_mac, ciaddr=assigned_ip)
        dhcp_request = scapy.layers.dhcp.DHCP(options=[("message-type", "request"), ("end")])
        eth_dhcp_request = eth_frame/ip_packet/proto_segment/bootp_message/dhcp_request
        self.request = eth_dhcp_request


    def write_dhcp_info(self, replys):
        """
        Parses the dhcp packet and writes the additional information into the object. 

        :param replys: list of the bootreplys (either offer or ack)
        :type replys: list[scapy.layers.l2.Ether]
        """
        
        if replys == None:
            raise ValueError
        
        # replys[0].show()
        # print(replys[0]["DHCP"].options[0])
        if replys[0]["DHCP"].options[0][1] == 2:            # options[0] --> first object in list of options (beeing "message-type"); options[0][1] --> value of "message-type" ... can be read in rfc2132
            self.offers = replys
            self.offerCounter = len(self.offers)
        elif (replys[0]["DHCP"].options[0][1] == 5) and len(replys) == 1:       # 
            self.ack = replys[0]
        else:
            print("wtf is going on ... this should never have been printed")
            raise ValueError
        
        first_reply = replys[0]
        self.new_ip = first_reply["BOOTP"].yiaddr
        clean_options = []
        for option in first_reply["DHCP"].options:
            if option != "pad":
                clean_options.append(option)
            
            if option[0] == "subnet_mask":
                self.cidr = self.subent_to_cidr(option[1])

        self.options = clean_options



    def send_packet(self, packet): 
        """
        This function sends a packet (bootrequest: dhcpoffer and dhcprequest), and waits for responses (bootreply) and returns these.

        :packet: the dhcp packet to be send 
        :type packet: scapy.layers.l2.Ether
        :returns:  list of replys to the requests ... there could be more than one reponse to the sent request
        :rtype: scapy.layers.l2.Ether
        """
        device_name = my_hw_info.get_nicInfo()[0]
        conf.checkIPaddr = False            # setting this conf is very important ... if not set, scapy can not match the dhcp offer to my sent dhcp discover
        ans, unans =srp(packet, iface=device_name, multi=True, timeout=my_hw_info.get_timeout())
        
        answers = []                        # creating a list for answers, as there could be multiple responses
        for send_recive in ans:             # itterating through all the responses
            answers.append(send_recive[1])  # answers are saved as send_recieve list ... first element beeing the request, second the response --> the one we are interested in
        
        # print(type(ans))               
        # print(type(ans[0]))
        bootreply = ans[0][1]
        self.write_dhcp_info(answers)
        # bootreply.show()
        # print(bootreply["IP"].proto)

        return answers


    def subent_to_cidr(self, mask):
        """
        Converts subnet mask to cidr. DHCP provides subnet mask, to bind ip however cidr notation is needed.

        :param mask: the subnet mask to be converted into cidr
        :type mask: str
        :returns: cidr notation of subnet mask
        :rtype: int
        """
        
        mask_bytes = mask.split(".")
        if len(mask_bytes) != 4:
            raise ValueError

        bin_bytes = [0, 0, 0, 0]
        for byte in range(len(mask_bytes)):
            bin_byte = bin(int(mask_bytes[byte]))[2:]
            bin_bytes[byte] = bin_byte.zfill(8)         # makes sure it has a length of 32 bits ... and sets up catching wrong subnetmasks

        bin_bits = "".join(bin_bytes)
        last_bit_zero = False
        cidr = 0
        for bit_index in range(32):                     # length of subnet mask as bits ... ensured by zfill(8) eralier # could also use range(len(bin_bytes)) ... 32 is more expressif
            if bin_bits[bit_index] == "1":
                if last_bit_zero == False:
                    cidr = cidr + 1
                else:
                    raise ValueError                    # this means the last bit was a 0 and the current bit is a 1 ... which is an impossible constellation in a subnetmask
            else:
                last_bit_zero = True

        return cidr


    def bind_ip(self):
        """
        Binds the new IP to the interface. 
        :return: void
        """
        new_ip = self.new_ip
        cidr = self.cidr
        if (new_ip or cidr) == None:
            raise ValueError
        subprocess.run(f"ip addr add {new_ip}/{cidr} dev {my_hw_info.get_nicInfo()[0]}", shell=True, check=True)


    def flush_old_id(self):
        """
        Remove all IPs from an interface.
        :return: void
        """
        subprocess.run(f"ip add flush dev {my_hw_info.get_nicInfo()[0]}")


# # dhcp usage: # here for test and debugging purposes

# my_dhcp = dhcp()
# my_dhcp.build_dhcp_discover()
# my_dhcp.offers = my_dhcp.send_packet(my_dhcp.discover)
# my_dhcp.build_dhcp_request()
# my_dhcp.ack = my_dhcp.send_packet(my_dhcp.request)


# print(type(ack[DHCP].options))         # type: ignore
# print(ack[DHCP].options)                # type: ignore

  
