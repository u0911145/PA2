# Import some POX stuff
from pox.core import core                     # Main POX object
import pox.openflow.libopenflow_01 as of      # OpenFlow 1.0 library
import pox.lib.packet as pkt                  # Packet parsing/construction
from pox.lib.addresses import EthAddr, IPAddr # Address types
import pox.lib.util as poxutil                # Various util functions
import pox.lib.revent as revent               # Event library
import pox.lib.recoco as recoco               # Multitasking library

# Create a logger for this component
log = core.getLogger()

switch_ip = IPAddr("10.0.0.10")
switch_mac = EthAddr("00:00:00:00:00:10")

servers = [(IPAddr("10.0.0.5"), EthAddr("00:00:00:00:00:05")),
           (IPAddr("10.0.0.6"), EthAddr("00:00:00:00:00:06"))]

server_index = 0

class LoadBalancer (object):
    def __init__(self):
        core.openflow.addListeners(self)

    def _handle_ConnectionUp(self, event):
        pass

    def _handle_PacketIn(self, event):
        packet = event.parsed

        if packet.type == packet.ARP_TYPE:
            self.handle_arp(packet, event)

        log.info("Received packet: %s", packet)

    def handle_arp(self, packet, event):
        arp_packet = packet.payload
        global server_index

        if arp_packet.opcode == arp_packet.REQUEST and arp_packet.protodst == switch_ip:
            log.info("Received ARP request for virtual IP")
            # ARP request for the virtual IP
            # Respond with the MAC address of the next server
            chosen_server_ip, chosen_server_mac = servers[server_index]
            server_index = (server_index + 1) % len(servers)

            # Create ARP reply
            arp_reply = pkt.arp()
            arp_reply.hwsrc = chosen_server_mac
            arp_reply.hwdst = arp_packet.hwsrc
            arp_reply.opcode = pkt.arp.REPLY
            arp_reply.protosrc = chosen_server_ip
            arp_reply.protodst = arp_packet.protosrc
            eth = pkt.ethernet(type=packet.ARP_TYPE, src=switch_mac, dst=arp_packet.hwsrc)
            eth.set_payload(arp_reply)

            log.info("Sending ARP reply for virtual IP")

            # Send ARP reply
            msg = of.ofp_packet_out()
            msg.data = eth.pack()
            msg.actions.append(of.ofp_action_output(port = event.port))
            msg.in_port = event.port
            event.connection.send(msg)

            log.info("Installed flow for virtual IP")

            # Install flow rules for this server
            self.install_flow(event, chosen_server_ip, chosen_server_mac, event.port, arp_packet.protosrc, event.port)

    def install_flow(self, event, server_ip, server_mac, server_port, client_ip, client_port):
        log.info("Installing flow: %s -> %s", client_ip, server_ip)

        # Rule for traffic from client to server
        msg = of.ofp_flow_mod()
        msg.match = of.ofp_match()
        msg.match.dl_type = pkt.ethernet.IP_TYPE
        msg.match.in_port = client_port
        msg.match.nw_dst = server_ip
        # actions
        msg.actions.append(of.ofp_action_dl_addr.set_dst(server_mac))
        msg.actions.append(of.ofp_action_nw_addr.set_dst(server_ip))
        msg.actions.append(of.ofp_action_output(port=server_port))
        event.connection.send(msg)

        log.info("Installing flow: %s -> %s", server_ip, client_ip)

        # Rule for traffic from server to client (assuming server port is known)
        msg = of.ofp_flow_mod()
        msg.match = of.ofp_match()
        msg.match.dl_type = pkt.ethernet.IP_TYPE
        msg.match.in_port = server_port
        msg.match.nw_src = server_ip
        msg.match.nw_dst = client_ip
        # actions
        msg.actions.append(of.ofp_action_dl_addr.set_src(switch_mac))
        msg.actions.append(of.ofp_action_nw_addr.set_src(switch_ip))
        msg.actions.append(of.ofp_action_output(port=client_port))
        event.connection.send(msg)

        log.info("Flow installed")
        pass

@poxutil.eval_args
def launch():
    core.registerNew(LoadBalancer)
