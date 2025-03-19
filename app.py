# Import some POX stuff
from pox.core import core                     # Main POX object
import pox.openflow.libopenflow_01 as of      # OpenFlow 1.0 library
import pox.lib.packet as pkt                  # Packet parsing/construction
from pox.lib.addresses import EthAddr, IPAddr # Address types
import pox.lib.util as poxutil                # Various util functions
import pox.lib.revent as revent               # Event library
import pox.lib.recoco as recoco               # Multitasking library
from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.arp import arp
from pox.lib.packet.ipv4 import ipv4
from pox.lib.addresses import IPAddr, EthAddr

# Create a logger for this component
log = core.getLogger()

VIRTUAL_IP = IPAddr("10.0.0.10")
VIRTUAL_MAC = EthAddr("00:00:00:00:00:10")

SERVER_IP = IPAddr("10.0.0.5")
SERVER_MAC = EthAddr("00:00:00:00:00:05")

class LoadBalancer (object):
    def __init__(self, connection):
        self.connection = connection
        connection.addListeners(self)
        log.info("Simple Load Balancer Initialized")

    def _handle_PacketIn(self, event):
        packet = event.parsed
        in_port = event.port

        log.debug(f"PacketIn: src={packet.src}, dst={packet.dst}, type={packet.type}, in_port={in_port}")

        if packet.type == ethernet.ARP_TYPE:
            self._handle_arp(event)
        elif packet.type == ethernet.IP_TYPE:
            self._handle_ip(event)

    def _handle_arp(self, event):
        arp_packet = event.parsed.payload

        if arp_packet.opcode == arp.REQUEST and arp_packet.protodst == VIRTUAL_IP:
            log.info(f"Handling ARP request for virtual IP {VIRTUAL_IP}")
            
            arp_reply = arp()
            arp_reply.opcode = arp.REPLY
            arp_reply.hwsrc = VIRTUAL_MAC
            arp_reply.hwdst = arp_packet.hwsrc
            arp_reply.protosrc = VIRTUAL_IP
            arp_reply.protodst = arp_packet.protosrc

            eth_reply = ethernet()
            eth_reply.type = ethernet.ARP_TYPE
            eth_reply.src = VIRTUAL_MAC
            eth_reply.dst = arp_packet.hwsrc
            eth_reply.payload = arp_reply

            msg = of.ofp_packet_out()
            msg.data = eth_reply.pack()
            msg.actions.append(of.ofp_action_output(port=event.port))
            self.connection.send(msg)

            log.info(f"Sent ARP reply: {VIRTUAL_IP} is-at {VIRTUAL_MAC}")

    def _handle_ip(self, event):
        ip_packet = event.parsed.payload

        if ip_packet.dstip == VIRTUAL_IP:
            log.info(f"Handling IP packet for virtual IP {VIRTUAL_IP}")

            # Install flow rule
            flow_mod = of.ofp_flow_mod()
            flow_mod.match.dl_type = ethernet.IP_TYPE
            flow_mod.match.nw_dst = VIRTUAL_IP
            flow_mod.actions.append(of.ofp_action_dl_addr.set_dst(SERVER_MAC))
            flow_mod.actions.append(of.ofp_action_nw_addr.set_dst(SERVER_IP))
            flow_mod.actions.append(of.ofp_action_output(port=of.OFPP_NORMAL))
            self.connection.send(flow_mod)

            # Forward the current packet
            msg = of.ofp_packet_out()
            msg.data = event.ofp
            msg.actions.append(of.ofp_action_dl_addr.set_dst(SERVER_MAC))
            msg.actions.append(of.ofp_action_nw_addr.set_dst(SERVER_IP))
            msg.actions.append(of.ofp_action_output(port=of.OFPP_NORMAL))
            self.connection.send(msg)

            log.info(f"Forwarded packet and installed flow rule: {ip_packet.srcip} -> {VIRTUAL_IP} (actual: {SERVER_IP})")

@poxutil.eval_args
def launch():
    def start_switch(event):
        log.info("Starting Load Balancer on %s", event.connection)
        LoadBalancer(event.connection)
    core.openflow.addListenerByName("ConnectionUp", start_switch)
