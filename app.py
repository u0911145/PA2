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
from pox.lib.addresses import IPAddr, EthAddr

# Create a logger for this component
log = core.getLogger()

VIRTUAL_IP = IPAddr("10.0.0.10")
VIRTUAL_MAC = EthAddr("00:00:00:00:00:10")
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

        log.debug(f"Received packet: type={packet.type}, in_port={in_port}")
        
        # Check if the packet is an ARP and if it is for the virtual IP
        if packet.type == ethernet.ARP_TYPE:
            if payload.opcode == arp.REQUEST and payload.protodst == VIRTUAL_IP:
                log.info(f"Handling ARP request for virtual IP {VIRTUAL_IP}")
                
                # Round-robin selection
                server_ip, server_mac = SERVERS[server_index]
                server_index = (server_index + 1) % len(SERVERS)

                log.info(f"Selected server: server_ip={server_ip}, server_mac={server_mac}")
                
                # Create ARP reply
                arp_reply = arp()
                arp_reply.opcode = arp.REPLY
                arp_reply.hwtype = payload.hwtype
                arp_reply.prototype = payload.prototype
                arp_reply.hwlen = payload.hwlen
                arp_reply.protolen = payload.protolen
                arp_reply.protosrc = VIRTUAL_IP
                arp_reply.protodst = payload.protosrc
                arp_reply.hwsrc = VIRTUAL_MAC
                arp_reply.hwdst = payload.hwsrc

                log.info(f"Created ARP reply: server_ip={server_ip}, server_mac={server_mac}")
                
                # Create Ethernet reply
                eth_reply = ethernet()
                eth_reply.type = ethernet.ARP_TYPE
                eth_reply.src = VIRTUAL_MAC
                eth_reply.dst = payload.hwsrc
                eth_reply.payload = arp_reply

                log.info(f"Created Ethernet reply: server_ip={server_ip}, server_mac={server_mac}")
                
                # Send
                msg = of.ofp_packet_out()
                msg.data = eth_reply.pack()
                msg.actions.append(of.ofp_action_output(port=in_port))
                self.connection.send(msg)

                log.info(f"Sent ARP reply: virtual_ip={VIRTUAL_IP}, virtual_mac={VIRTUAL_MAC}")
                log.info(f"ARP reply details: src={eth_reply.src}, dst={eth_reply.dst}, "
                        f"hwsrc={arp_reply.hwsrc}, hwdst={arp_reply.hwdst}, "
                        f"protosrc={arp_reply.protosrc}, protodst={arp_reply.protodst}")
                
                # Install a flow rule to handle future ARP requests
                flow_mod = of.ofp_flow_mod()
                flow_mod.match.dl_type = ethernet.ARP_TYPE
                flow_mod.match.nw_dst = VIRTUAL_IP
                flow_mod.actions.append(of.ofp_action_output(port=of.OFPP_CONTROLLER))
                self.connection.send(flow_mod)
                return
        
        # Check if the packet is an IP and if it is for the virtual IP
        elif packet.type == ethernet.IP_TYPE:
            if payload.dstip == VIRTUAL_IP:
                log.info(f"Handling IP packet for virtual IP {VIRTUAL_IP}")

                # Round-robin selection
                server_ip, server_mac = SERVERS[server_index]
                server_index = (server_index + 1) % len(SERVERS)

                log.info(f"Selected server: server_ip={server_ip}, server_mac={server_mac}")
                
                # Install OpenFlow rules
                msg = of.ofp_flow_mod()
                msg.match.dl_type = ethernet.IP_TYPE
                msg.match.nw_dst = VIRTUAL_IP
                msg.actions.append(of.ofp_action_nw_addr.set_dst(server_ip))
                msg.actions.append(of.ofp_action_dl_addr.set_dst(server_mac))
                msg.actions.append(of.ofp_action_output(port=event.port))
                self.connection.send(msg)

                log.info(f"Installed flow rule: server_ip={server_ip}, server_mac={server_mac}")

                # Forward the current packet
                msg = of.ofp_packet_out()
                msg.data = event.ofp
                msg.actions.append(of.ofp_action_dl_addr.set_dst(server_mac))
                msg.actions.append(of.ofp_action_nw_addr.set_dst(server_ip))
                msg.actions.append(of.ofp_action_output(port=of.OFPP_NORMAL))
                self.connection.send(msg)
                return
            
        log.info("Packet not handled by load balancer")

@poxutil.eval_args
def launch():
    def start_switch(event):
        log.info("Starting Load Balancer on %s", event.connection)
        LoadBalancer(event.connection)
    core.openflow.addListenerByName("ConnectionUp", start_switch)
