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
        self.mac_to_port = {}  # MAC address to port mapping
        connection.addListeners(self)
        log.info("Load Balancer Initialized")

    def _handle_PacketIn(self, event):
        packet = event.parsed
        in_port = event.port

        self.mac_to_port[packet.src] = in_port

        log.debug(f"PacketIn: src={packet.src}, dst={packet.dst}, type={packet.type}, in_port={in_port}")

        if packet.type == ethernet.ARP_TYPE:
            self._handle_arp(event)
        elif packet.type == ethernet.IP_TYPE:
            self._handle_ip(event)
        else:
            log.debug("Packet not handled by load balancer")

    def _handle_arp(self, event):
        packet = event.parsed
        arp_packet = packet.payload

        if arp_packet.opcode == arp.REQUEST and arp_packet.protodst == VIRTUAL_IP:
            log.info(f"Handling ARP request for virtual IP {VIRTUAL_IP}")
            self._send_arp_reply(event, arp_packet)

    def _send_arp_reply(self, event, arp_request):
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

    def _handle_ip(self, event):
        packet = event.parsed
        ip_packet = packet.payload

        if ip_packet.dstip == VIRTUAL_IP:
            log.info(f"Handling IP packet for virtual IP {VIRTUAL_IP}")
            self._load_balance(event, ip_packet)
        elif ip_packet.srcip in [server[0] for server in SERVERS]:
            log.info(f"Handling return traffic from server {ip_packet.srcip}")
            self._handle_server_return_traffic(event, ip_packet)

    def _load_balance(self, event, ip_packet):
        global server_index
        server_ip, server_mac = SERVERS[server_index]
        server_index = (server_index + 1) % len(SERVERS)

        client_mac = event.parsed.src
        client_ip = ip_packet.srcip

        # Install flow rule for client to server
        self._install_flow_rule(client_ip, VIRTUAL_IP, server_ip, server_mac, event.port)

        # Install flow rule for server to client
        self._install_flow_rule(server_ip, client_ip, VIRTUAL_IP, VIRTUAL_MAC, self.mac_to_port[server_mac])

        log.info(f"Installed flow rules: {client_ip} <-> {VIRTUAL_IP} (actual: {server_ip})")

        # Forward the current packet
        self._send_packet(event, server_mac, server_ip)

    def _install_flow_rule(self, src_ip, dst_ip, new_dst_ip, new_dst_mac, out_port):
        flow_mod = of.ofp_flow_mod()
        flow_mod.match.dl_type = ethernet.IP_TYPE
        flow_mod.match.nw_src = src_ip
        flow_mod.match.nw_dst = dst_ip
        flow_mod.actions.append(of.ofp_action_dl_addr.set_dst(new_dst_mac))
        flow_mod.actions.append(of.ofp_action_nw_addr.set_dst(new_dst_ip))
        flow_mod.actions.append(of.ofp_action_output(port=out_port))
        self.connection.send(flow_mod)

    def _send_packet(self, event, dst_mac, dst_ip):
        msg = of.ofp_packet_out()
        msg.data = event.ofp
        msg.actions.append(of.ofp_action_dl_addr.set_dst(dst_mac))
        msg.actions.append(of.ofp_action_nw_addr.set_dst(dst_ip))
        msg.actions.append(of.ofp_action_output(port=self.mac_to_port[dst_mac]))
        self.connection.send(msg)

    def _handle_server_return_traffic(self, event, ip_packet):
        client_ip = ip_packet.dstip
        client_mac = None
        for mac, port in self.mac_to_port.items():
            if port == event.port:
                client_mac = mac
                break

        if client_mac:
            # Modify packet to appear as if it's coming from the virtual IP
            msg = of.ofp_packet_out()
            msg.data = event.ofp
            msg.actions.append(of.ofp_action_dl_addr.set_src(VIRTUAL_MAC))
            msg.actions.append(of.ofp_action_nw_addr.set_src(VIRTUAL_IP))
            msg.actions.append(of.ofp_action_output(port=self.mac_to_port[client_mac]))
            self.connection.send(msg)
            log.info(f"Forwarded return traffic to client {client_ip}")
        else:
            log.warning(f"Unable to find client MAC for IP {client_ip}")

@poxutil.eval_args
def launch():
    def start_switch(event):
        log.info("Starting Load Balancer on %s", event.connection)
        LoadBalancer(event.connection)
    core.openflow.addListenerByName("ConnectionUp", start_switch)
