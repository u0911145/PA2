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

servers = [(IPAddr("10.0.0.5"), EthAddr("00:00:00:00:00:05"), 5),
           (IPAddr("10.0.0.6"), EthAddr("00:00:00:00:00:06"), 6)]

server_index = 0
client_server_map = {}

class LoadBalancer (object):
    def __init__(self):
        core.openflow.addListeners(self)

    def _handle_ConnectionUp(self, event):
        log.info("Switch connected")

    def _handle_PacketIn(self, event):
        packet = event.parsed
        log.info(f"Received packet on port {event.port}: {packet}")
    
        if packet.type == pkt.ethernet.ARP_TYPE:
            log.info("Handling ARP packet")
            self.handle_arp(packet, event)
            return
        
        if packet.type == pkt.ethernet.IP_TYPE:
            log.info("Handling IP packet")
            self.handle_ip(packet, event)
            return

    def handle_arp(self, packet, event):
        global server_index, client_server_map
        arp_packet = packet.payload
        log.info(f"ARP request details: {arp_packet}")

        if arp_packet.opcode == pkt.arp.REQUEST:
            requested_ip = arp_packet.protodst

            if requested_ip == switch_ip:
                log.info("Received ARP request for virtual IP")
                client_ip = arp_packet.protosrc
                if client_ip not in client_server_map:
                    client_server_map[client_ip] = servers[server_index]
                    server_index = (server_index + 1) % len(servers)
                chosen_server_ip, chosen_server_mac = client_server_map[client_ip]
            else:
                log.info(f"Received ARP request for client IP {requested_ip}")
                chosen_server_ip, chosen_server_mac = requested_ip, switch_mac
            
            arp_reply = pkt.arp()
            arp_reply.hwsrc = chosen_server_mac
            arp_reply.hwdst = arp_packet.hwsrc
            arp_reply.opcode = pkt.arp.REPLY
            arp_reply.protosrc = switch_ip
            arp_reply.protodst = arp_packet.protosrc

            ether = pkt.ethernet()
            ether.type = pkt.ethernet.ARP_TYPE
            ether.dst = packet.src
            ether.src = chosen_server_mac
            ether.payload = arp_reply

            log.info(f"Sending ARP reply: {arp_reply}")

            msg = of.ofp_packet_out()
            msg.data = ether.pack()
            msg.actions.append(of.ofp_action_output(port=of.OFPP_ALL))
            event.connection.send(msg)

            self.install_flow(event, chosen_server_ip, chosen_server_mac, of.OFPP_ALL, client_ip, of.OFPP_ALL)

    def handle_ip(self, packet, event):
        global client_server_map
    
        ip_packet = packet.payload
        client_ip = ip_packet.srcip
    
        if client_ip in client_server_map:
            chosen_server_ip, chosen_server_mac = client_server_map[client_ip]
        else:
            chosen_server_ip, chosen_server_mac, server_port = servers[server_index]
            client_server_map[client_ip] = (chosen_server_ip, chosen_server_mac, server_port)
    
        log.info(f"Forwarding IP packet from {client_ip} to {chosen_server_ip} via port {server_port}")
    
        msg = of.ofp_packet_out()
        msg.data = event.data
        msg.actions.append(of.ofp_action_dl_addr.set_dst(chosen_server_mac))
        msg.actions.append(of.ofp_action_nw_addr.set_dst(chosen_server_ip))
        msg.actions.append(of.ofp_action_output(port=of.OFPP_ALL))
        event.connection.send(msg)
    
        self.install_flow(event, chosen_server_ip, chosen_server_mac, of.OFPP_ALL, client_ip, of.OFPP_ALL)

    def install_flow(self, event, server_ip, server_mac, server_port, client_ip, client_port):
        log.info(f"Installing forward flow: {client_ip} -> {server_ip} via port {server_port}")

        msg = of.ofp_flow_mod()
        msg.match = of.ofp_match()
        msg.match.dl_type = pkt.ethernet.IP_TYPE
        msg.match.in_port = client_port
        msg.match.nw_dst = switch_ip
        msg.actions.append(of.ofp_action_dl_addr.set_dst(server_mac))
        msg.actions.append(of.ofp_action_nw_addr.set_dst(server_ip))
        msg.actions.append(of.ofp_action_output(port=server_port))
        event.connection.send(msg)

        log.info(f"Installing return flow: {server_ip} -> {client_ip} via port {client_port}")

        msg = of.ofp_flow_mod()
        msg.match = of.ofp_match()
        msg.match.dl_type = pkt.ethernet.IP_TYPE
        msg.match.in_port = server_port
        msg.match.nw_src = server_ip
        msg.match.nw_dst = client_ip
        msg.actions.append(of.ofp_action_dl_addr.set_src(switch_mac))
        msg.actions.append(of.ofp_action_nw_addr.set_src(switch_ip))
        msg.actions.append(of.ofp_action_output(port=client_port))
        event.connection.send(msg)

        log.info("Flow installed successfully")

@poxutil.eval_args
def launch():
    log.info("Starting Load Balancer")
    core.registerNew(LoadBalancer)