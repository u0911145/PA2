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
                self._handle_arp_request(event, payload)
                return
        
        # Check if the packet is an IP and if it is for the virtual IP
        elif packet.type == ethernet.IP_TYPE:
            if payload.dstip == VIRTUAL_IP:
                log.info(f"Handling IP packet for virtual IP {VIRTUAL_IP}")
                self._handle_ip_packet(event, payload)
                return
            
        log.info("Packet not handled by load balancer")

    def _handle_arp_request(self, event, arp_request):
        arp_reply = arp()
        arp_reply.opcode = arp.REPLY
        arp_reply.hwsrc = VIRTUAL_MAC
        arp_reply.hwdst = arp_request.hwsrc
        arp_reply.protosrc = VIRTUAL_IP
        arp_reply.protodst = arp_request.protosrc

        eth_reply = ethernet()
        eth_reply.type = ethernet.ARP_TYPE
        eth_reply.src = VIRTUAL_MAC
        eth_reply.dst = arp_request.hwsrc
        eth_reply.payload = arp_reply

        msg = of.ofp_packet_out()
        msg.data = eth_reply.pack()
        msg.actions.append(of.ofp_action_output(port=event.port))
        self.connection.send(msg)

        log.info(f"Sent ARP reply: {VIRTUAL_IP} is-at {VIRTUAL_MAC}")

    def _handle_ip_packet(self, event, ip_packet):
        global server_index
        server_ip, server_mac = SERVERS[server_index]
        server_index = (server_index + 1) % len(SERVERS)

        client_mac = event.parsed.src
        client_ip = ip_packet.srcip

        # Install flow rule for client to server
        flow_mod = of.ofp_flow_mod()
        flow_mod.match.dl_type = ethernet.IP_TYPE
        flow_mod.match.nw_dst = VIRTUAL_IP
        flow_mod.match.nw_src = client_ip
        flow_mod.actions.append(of.ofp_action_dl_addr.set_dst(server_mac))
        flow_mod.actions.append(of.ofp_action_nw_addr.set_dst(server_ip))
        flow_mod.actions.append(of.ofp_action_output(port=self._get_port_for_mac(server_mac)))
        self.connection.send(flow_mod)

        # Install flow rule for server to client
        flow_mod = of.ofp_flow_mod()
        flow_mod.match.dl_type = ethernet.IP_TYPE
        flow_mod.match.nw_src = server_ip
        flow_mod.match.nw_dst = client_ip
        flow_mod.actions.append(of.ofp_action_dl_addr.set_src(VIRTUAL_MAC))
        flow_mod.actions.append(of.ofp_action_nw_addr.set_src(VIRTUAL_IP))
        flow_mod.actions.append(of.ofp_action_output(port=event.port))
        self.connection.send(flow_mod)

        log.info(f"Installed flow rules: {client_ip} <-> {VIRTUAL_IP} (actual: {server_ip})")

        # Forward the current packet
        msg = of.ofp_packet_out()
        msg.data = event.ofp
        msg.actions.append(of.ofp_action_dl_addr.set_dst(server_mac))
        msg.actions.append(of.ofp_action_nw_addr.set_dst(server_ip))
        msg.actions.append(of.ofp_action_output(port=self._get_port_for_mac(server_mac)))
        self.connection.send(msg)

    def _get_port_for_mac(self, mac):
        # This is a simplified version. In a real scenario, you'd maintain a MAC-to-port mapping.
        for i, (_, server_mac) in enumerate(SERVERS):
            if server_mac == mac:
                return i + 1  # Assuming server ports start from 1
        return of.OFPP_FLOOD  # If not found, flood the packet

@poxutil.eval_args
def launch():
    def start_switch(event):
        log.info("Starting Load Balancer on %s", event.connection)
        LoadBalancer(event.connection)
    core.openflow.addListenerByName("ConnectionUp", start_switch)
