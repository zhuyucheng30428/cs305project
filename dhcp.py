from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import udp
from ryu.lib.packet import dhcp
from ofctl_utilis import ipv4_text_to_int
from ofctl_utilis import ipv4_int_to_text


class Config():
    controller_macAddr = '7e:49:b3:f0:f9:99'  # don't modify, a dummy mac address for fill the mac enrty
    dns = '8.8.8.8'  # don't modify, just for the dns entry
    start_ip = '192.168.1.2'  # can be modified
    end_ip = '192.168.1.100'  # can be modified
    netmask = '255.255.255.0'  # can be modified
    # new set of ip address
    set = {""}

    # You may use above attributes to configure your DHCP server.
    # You can also add more attributes like "lease_time" to support bouns function.


class DHCPServer:
    hardware_addr = Config.controller_macAddr
    start_ip = Config.start_ip
    end_ip = Config.end_ip
    netmask = Config.netmask
    dns = Config.dns
    set = Config.set

    @classmethod
    def assemble_ack(cls, pkt, datapath, port):
        # Generate DHCP ACK packet
        ack_pkt = packet.Packet()
        ack_pkt.add_protocol(ethernet.ethernet(ethertype=pkt.protocols[0].ethertype,
                                               dst=pkt.protocols[0].src,
                                               src=cls.hardware_addr))
        ack_pkt.add_protocol(ipv4.ipv4(dst=pkt.protocols[1].dst,
                                       src=pkt.protocols[1].src,
                                       proto=pkt.protocols[1].proto))
        ack_pkt.add_protocol(udp.udp(dst_port=pkt.protocols[2].dst_port,
                                     src_port=pkt.protocols[2].src_port))
        ack_pkt.add_protocol(dhcp.dhcp(op=dhcp.DHCP_ACK,
                                       chaddr=pkt.protocols[3].chaddr,
                                       siaddr=pkt.protocols[3].siaddr,
                                       boot_file=pkt.protocols[3].boot_file,
                                       yiaddr=pkt.protocols[3].yiaddr,
                                       giaddr=pkt.protocols[3].giaddr,
                                       xid=pkt.protocols[3].xid,
                                       options=pkt.protocols[3].options))
        return ack_pkt

    @classmethod
    def assemble_offer(cls, pkt, datapath):
        # find a free ip address
        ip = cls.start_ip
        while ip in cls.set:
            ip = ipv4_int_to_text(ipv4_text_to_int(ip) + 1)
        cls.set.add(ip)
        # Generate DHCP OFFER packet
        offer_pkt = packet.Packet()
        offer_pkt.add_protocol(ethernet.ethernet(ethertype=pkt.protocols[0].ethertype,
                                                 dst=pkt.protocols[0].src,
                                                 src=cls.hardware_addr))
        offer_pkt.add_protocol(ipv4.ipv4(dst=pkt.protocols[1].dst,
                                         src=pkt.protocols[1].src,
                                         proto=pkt.protocols[1].proto))
        offer_pkt.add_protocol(udp.udp(dst_port=pkt.protocols[2].dst_port,
                                       src_port=pkt.protocols[2].src_port))
        offer_pkt.add_protocol(dhcp.dhcp(op=dhcp.DHCP_OFFER,
                                         chaddr=pkt.protocols[3].chaddr,
                                         siaddr=pkt.protocols[3].siaddr,
                                         boot_file=pkt.protocols[3].boot_file,
                                         yiaddr=ip,
                                         giaddr=pkt.protocols[3].giaddr,
                                         xid=pkt.protocols[3].xid,
                                         options=pkt.protocols[3].options))
        return offer_pkt

    @classmethod
    def handle_dhcp(cls, datapath, port, pkt):
        #   TODO: Specify the type of received DHCP packet
        # extract the DHCP packet from the received packet
        dhcp_pkt = pkt.get_protocol(dhcp.dhcp)
        # determine the type of DHCP packet
        if dhcp_pkt:
            if dhcp_pkt.op == dhcp.DHCP_DISCOVER:
                # generate DHCP OFFER packet
                offer_pkt = cls.assemble_offer(pkt, datapath)
                cls._send_packet(datapath, port, offer_pkt)
            elif dhcp_pkt.op == dhcp.DHCP_REQUEST:
                # generate DHCP ACK packet
                ack_pkt = cls.assemble_ack(pkt, datapath, port)
                cls._send_packet(datapath, port, ack_pkt)
            else:
                pass
        # You may choose a valid IP from IP pool and generate DHCP OFFER packet
        # Or generate a DHCP ACK packet
        # Finally send the generated packet to the host by using _send_packet method

    @classmethod
    def _send_packet(cls, datapath, port, pkt):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        if isinstance(pkt, str):
            pkt = pkt.encode()
        pkt.serialize()
        data = pkt.data
        actions = [parser.OFPActionOutput(port=port)]
        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=ofproto.OFPP_CONTROLLER,
                                  actions=actions,
                                  data=data)
        datapath.send_msg(out)
