from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.packet.ethernet import ethernet, ETHER_BROADCAST
from pox.lib.packet.arp import arp
from pox.lib.packet.ipv4 import ipv4
from pox.lib.addresses import IPAddr, EthAddr

log = core.getLogger()

VIRTUAL_IP = IPAddr("10.0.0.10")
SERVERS = [(IPAddr("10.0.0.5"), EthAddr("00:00:00:00:00:05")),
           (IPAddr("10.0.0.6"), EthAddr("00:00:00:00:00:06"))]
server_index = 0

class LoadBalancer (object):
    def __init__(self, connection):
        self.connection = connection
        connection.addListeners(self)
        log.info("Load Balancer Initialized")
    
    def _handle_PacketIn(self, event):
        global server_index
        packet = event.parsed
        in_port = event.port

        payload = packet.payload
        
        if packet.type == ethernet.ARP_TYPE:
            if payload.opcode == arp.REQUEST and payload.protodst == VIRTUAL_IP:
                # Round-robin selection
                server_ip, server_mac = SERVERS[server_index]
                server_index = (server_index + 1) % len(SERVERS)
                
                # Create ARP reply
                arp_reply = arp()
                arp_reply.opcode = arp.REPLY
                arp_reply.protosrc = VIRTUAL_IP
                arp_reply.protodst = payload.protosrc
                arp_reply.hwsrc = server_mac
                arp_reply.hwdst = payload.hwsrc
                
                eth_reply = ethernet()
                eth_reply.type = ethernet.ARP_TYPE
                eth_reply.src = server_mac
                eth_reply.dst = payload.hwsrc
                eth_reply.payload = arp_reply
                
                msg = of.ofp_packet_out()
                msg.data = eth_reply.pack()
                msg.actions.append(of.ofp_action_output(port=in_port))
                self.connection.send(msg)
                return
        
        elif packet.type == ethernet.IP_TYPE:
            if payload.dstip == VIRTUAL_IP:
                server_ip, server_mac = SERVERS[server_index]
                server_index = (server_index + 1) % len(SERVERS)
                
                # Install OpenFlow rules
                msg = of.ofp_flow_mod()
                msg.match.dl_type = ethernet.IP_TYPE
                msg.match.nw_dst = VIRTUAL_IP
                msg.actions.append(of.ofp_action_nw_addr.set_dst(server_ip))
                msg.actions.append(of.ofp_action_dl_addr.set_dst(server_mac))
                msg.actions.append(of.ofp_action_output(port=event.port))
                self.connection.send(msg)
                return

def launch():
    def start_switch(event):
        log.info("Starting Load Balancer on %s", event.connection)
        LoadBalancer(event.connection)
    core.openflow.addListenerByName("ConnectionUp", start_switch)
