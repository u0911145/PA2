# Import some POX stuff
from pox.core import core
import pox.openflow.libopenflow_01 as of
import pox.lib.packet as pkt
from pox.lib.addresses import EthAddr, IPAddr
import pox.lib.util as poxutil

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
        log.info(f"Received packet on port {event.port}: {packet.payload}")
    
        if packet.type == pkt.ethernet.ARP_TYPE:
            log.info("Handling ARP packet")
            self.handle_arp(packet, event)
            return
        
    def assign_client_server(self, client_key):
        # Assign client to server, in round robin fashion
        global client_server_map
        global server_index
        client_server_map[client_key] = servers[server_index]
        server_index = (server_index + 1) % len(servers)
        return client_server_map[client_key]

    def handle_arp(self, packet, event):
        global server_index, client_server_map
        arp_packet = packet.payload

        if arp_packet.opcode == pkt.arp.REQUEST:
            # Get info
            requested_ip = arp_packet.protodst
            client_ip = arp_packet.protosrc
            client_mac = arp_packet.hwsrc

            chosen_server_ip = switch_ip
            chosen_server_mac = switch_mac

            # Check if sent to switch
            if requested_ip == switch_ip:
                log.info("Received ARP request for virtual IP")
                chosen_server_ip, chosen_server_mac, chosen_port = self.assign_client_server((client_ip, client_mac))

                # Install openflow rules
                log.info(f"Forwarding IP packet from {client_ip} to {chosen_server_ip} via port {chosen_port}")
            
                # Client -> Server
                msg = of.ofp_flow_mod()
                msg.match.dl_type = pkt.ethernet.IP_TYPE
                msg.match.nw_dst = switch_ip
                msg.match.in_port = event.port
                
                # Actions
                msg.actions.append(of.ofp_action_nw_addr.set_dst(chosen_server_ip))
                msg.actions.append(of.ofp_action_dl_addr.set_dst(chosen_server_mac))
                msg.actions.append(of.ofp_action_output(port=chosen_port))
                
                event.connection.send(msg)
                
                # Server -> Client
                msg = of.ofp_flow_mod()
                msg.match.dl_type = pkt.ethernet.IP_TYPE
                msg.match.nw_src = chosen_server_ip
                msg.match.in_port = chosen_port
                
                # Actions
                msg.actions.append(of.ofp_action_nw_addr.set_src(switch_ip))
                msg.actions.append(of.ofp_action_dl_addr.set_src(switch_mac))
                msg.actions.append(of.ofp_action_output(port=event.port))
                
                event.connection.send(msg)

                # Reset ip for ARP
                chosen_server_ip = switch_ip
            else:
                log.info(f"Received ARP request for client IP {requested_ip}")
                # Request is from server, get client ip and client map
                for client_key in client_server_map:
                    if client_key[0] == requested_ip:
                        chosen_server_ip, chosen_server_mac = client_key
                        break
            
            # Create ARP reply
            arp_reply = pkt.arp()
            arp_reply.hwsrc = chosen_server_mac
            arp_reply.hwdst = arp_packet.hwsrc
            arp_reply.opcode = pkt.arp.REPLY
            arp_reply.protosrc = chosen_server_ip
            arp_reply.protodst = arp_packet.protosrc

            # Create ethernet
            ether = pkt.ethernet()
            ether.type = pkt.ethernet.ARP_TYPE
            ether.dst = packet.src
            ether.src = chosen_server_mac
            ether.payload = arp_reply

            log.info(f"Sending ARP reply: {arp_reply}")
            
            # Send
            msg = of.ofp_packet_out()
            msg.data = ether.pack()
            msg.actions.append(of.ofp_action_output(port=event.port))
            event.connection.send(msg)

@poxutil.eval_args
def launch():
    log.info("Starting Load Balancer")
    core.registerNew(LoadBalancer)
