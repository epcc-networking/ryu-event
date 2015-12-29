import os
import time
import logging
from random import randint

from collections import defaultdict

from ryu.base import app_manager
from ryu.controller import event,ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls

import ryu.topology.event as topo_event
import ryu.topology.switches as topo_switches
import ryu.topology.api as topo_api

from ryu.lib.packet import packet,ethernet,ether_types
from ryu.lib.packet import lldp,arp,ipv4,tcp,udp,in_proto
from ryu.lib.mac import haddr_to_bin
from ryu.lib.hub import spawn
from ryu.lib import ip

from ryu import utils,cfg

import event_message_ofp10 as evt_10
import event_message_ofp13 as evt_13

import common

EPCC_VENDOR_ID = 0xEBCC3118
LINK_TIME_OUT = 10

ARP_TIMEOUT = 120

DEFAULT_SPECIFIED_FLOW_PRIORITY = 32768

PORT_PEER_HOST = 0
PORT_PEER_SWITCH = 1
PORT_PEER_CONTROLLER = 2

METHOD_RANDOM = "RANDOM"
METHOD_HASH = "HASH"
METHOD_FIRST_FIT = "FIRST_FIT"

LOG = logging.getLogger(__name__)

fat_tree = {'edges':set([]),'aggrs':set([]),'cores':set([]),'build_done':False}
layered_topo = []

                
class ForwardingBasic(app_manager.RyuApp):
    _EVENTS = [
        common.EventElephantDetectRequest,
        common.EventStartScheduling,
        common.EventPauseScheduling,
    ]


    def __init__(self,*args,**kwargs):
        super(ForwardingBasic,self).__init__(args,kwargs)
        self.CONF.register_opts([
            cfg.StrOpt("topology",default = None,
                help = "Specified network topology",
                )
            ])
        self.topo = "fattree"
        self.topo = None
        self.name = "Forwarding-Basic"

        self.spanning_tree_done = True
        self.spanning_tree_links = set([])
        self.mac_to_port = {}
        self.mac_to_port.setdefault(0,{})

        self.install_port_events = True
        self.total_links = 0
        self.poll_port_stats = True
        self.link_rate_out_file = open("logs/link_rate.out.%s" %time.strftime("%Y%m%d_%H%M%S") ,'w')

        if self.topo is None:
            self.logger.info("No topology specified.")
        else:
            self.logger.info("Specified topology is %s" %self.topo)
            if self.topo == 'fattree':
                self.expected_links = 64
                self.fat_tree_k = 4
        spawn(self.send_port_req_loop)

    def calc_next_hop(self,src_dpid,dst_dpid):
        self.logger.info("calculate paths from %016x to %016x " %(src_dpid,dst_dpid) )
        #Dijkstra algorithm?
        dist = defaultdict(lambda: float('+inf'))
        prev = defaultdict(lambda: None)
        path_found = defaultdict(lambda: False)
        adj = common.adj

        dist[src_dpid] = 0
        u = src_dpid
        t = None
        path_done = False
        min_dist = float('+inf')
        path_found[u] = True
        if src_dpid == dst_dpid:
            return [ src_dpid, ]

        while not path_done:
            path_done = True
            min_dist = float('+inf')
            #self.logger.info("====Find path through %016x" %u)
            for v in adj[u].keys():
                if adj[u][v] is not None:
                    w = adj[u][v].rate * 0 + 1.0 #any attributes 
                    if dist[v] > dist[u] + w:
                        dist[v] = dist[u] + w
                        prev[v] = [u]
                        #self.logger.info("Go to %016x through %016x" %(v,u))
                    elif dist[v] == dist[u] + w:
                        prev[v].append(u)
                        #self.logger.info("Go to %016x also through %016x" %(v,u))

            u = None
            for v in common.switch_list.keys():
                if dist[v] < min_dist and path_found[v] == False: 
                    min_dist = dist[v]
                    u = v

            if u is not None:
                #self.logger.info("Go to %016x , path found" %(u))
                path_found[u] = True
                path_done = False

        if prev[dst_dpid] is None:
            #self.logger.info("path not found")
            return []
        else:
            #self.logger.info("last hop: %s" %prev[dst_dpid])
            pass

        def find_next_hop(src,dst):
            if src in prev[dst]:
                return [dst]
            else:
                res = []
                for v in prev[dst]:
                    next_hops = find_next_hop(src,v)
                    for next_hop in next_hops:
                        if next_hops not in res:
                            res.append(next_hop)
                return res

        return list(find_next_hop(src_dpid,dst_dpid))

    def calc_spanning_tree(self,re_calculate = False):
        if self.spanning_tree_done and not re_calculate:
            return self.spanning_tree_links

        else:
            switches_in_tree = set([])
            check_dpid_list = []
            root_switch = None
            tree_links = set([])

            #self.logger.info("calculate spanning tree for %d switches" %len(common.switch_list))

            for switch_dpid in common.switch_list.keys():
                root_switch_dpid = switch_dpid
                break

            front = 0
            check_dpid_list.append(root_switch_dpid)

            #use BFS to generate spanning tree.

            while front < len(check_dpid_list):
                u = check_dpid_list[front]
                switches_in_tree.add(u)
                for v in common.adj[u].keys():
                    if common.adj[u][v] is not None and common.adj[v][u] is not None:
                        if v not in switches_in_tree:
                            switches_in_tree.add(v)
                            check_dpid_list.append(v)
                            tree_links.add(common.adj[u][v])

                front += 1

            if len(switches_in_tree) < len(common.switch_list):
                self.logger.info("calculate spanning tree failed!")
                self.spanning_tree_done = False
                return None

            else:
                self.logger.info("===Spanning tree done===")
                self.spanning_tree_done = True
                self.spanning_tree_links = tree_links

                for dpid in common.switch_list.keys():
                    switch = common.switch_list[dpid]
                    for port_no in switch.ports:
                        port = switch.ports[port_no]
                        if port.peer is not None and port.peer[0] == PORT_PEER_HOST:
                            port.enable_flood()

                        if port.peer is not None and port.peer[0] == PORT_PEER_SWITCH:
                            peer_dpid = port.peer[1][0]
                            peer_port_no = port.peer[1][1]
                            if common.adj[dpid][peer_dpid] in tree_links or common.adj[peer_dpid][dpid] in tree_links:
                                #self.logger.info("Link %016x:%d--%016x:%d in spanning tree, enable flooding on switch %016x port %d"
                                #    %(dpid,port_no,peer_dpid,peer_port_no,dpid,port_no) )
                                port.enable_flood()
                            else:
                                #self.logger.info("Link %016x:%d--%016x:%d not in spanning tree, disable flooding on switch %016x port %d"
                                #    %(dpid,port_no,peer_dpid,peer_port_no,dpid,port_no) )                                
                                port.disable_flood()


                return tree_links

    def build_fat_tree_topo(self):
        for switch_dpid in common.switch_list:
            switch = common.switch_list[switch_dpid]
            if switch.possible_edge:
                common.fat_tree['edges'].add(switch)
                switch.layer = 1
                switch.up_ports = []
                self.logger.info("Switch %016x is a edge switch." %switch_dpid)

        for switch in common.fat_tree['edges']:
            dpid = switch.datapath.id
            for neighbor_dpid in common.adj[dpid]:
                neighbor_switch = common.switch_list[neighbor_dpid]
                link = common.adj[dpid][neighbor_dpid]
                port_no = link.src_port_no
                switch.up_ports.append(port_no)
                if neighbor_switch not in common.fat_tree['aggrs']:
                    common.fat_tree['aggrs'].add(neighbor_switch)
                    self.logger.info("switch %016x is on aggregation layer." %neighbor_dpid)

        for switch in common.fat_tree['aggrs']:
            dpid = switch.datapath.id
            for neighbor_dpid in common.adj[dpid]:
                neighbor_switch = common.switch_list[neighbor_dpid]
                if neighbor_switch not in common.fat_tree['edges']:
                    link = common.adj[dpid][neighbor_dpid]
                    port_no = link.src_port_no
                    switch.up_ports.append(port_no)
                    #self.logger.info("Aggr switch %016x go up through port %d" %(dpid,port_no))
                    if neighbor_switch not in common.fat_tree['cores']:
                        common.fat_tree['cores'].add(neighbor_switch)
                        self.logger.info("switch %016x is on core layer." %neighbor_dpid)

        for switch in common.fat_tree['edges']:
            i = 1
            for other_switch in common.fat_tree['edges']:
                if switch.datapath.id != other_switch.datapath.id:
                    ecmp_group_id = 0xec390000 + i
                    switch.up_group_ids[other_switch.datapath.id] = ecmp_group_id
                    #self.logger.info("Go to switch %016x through group %08x" %(other_switch.datapath.id,ecmp_group_id) )
                    i += 1
            self.send_event_to_observers(common.EventElephantDetectRequest(switch.datapath))


        for switch in common.fat_tree['aggrs']:
            i = 1
            dpid = switch.datapath.id
            for edge_switch in common.fat_tree['edges']:
                edge_dpid = edge_switch.datapath.id
                if common.adj[dpid][edge_dpid] is not None:
                    #self.logger.info("Edge switch %016x is under aggergation switch %016x" %(edge_dpid,dpid) )
                    pass
                else:
                    ecmp_group_id = 0xec390000 + i
                    switch.up_group_ids[edge_dpid] = ecmp_group_id
                    #self.logger.info("Go to switch %016x through group %08x" %(edge_dpid,ecmp_group_id))
                    i += 1

        for switch_dpid in common.switch_list:
            switch = common.switch_list[switch_dpid]
            if switch in common.fat_tree['edges'] or switch in common.fat_tree['aggrs']:
                if switch.datapath.ofproto.OFP_VERSION >= 0x02:
                    datapath = switch.datapath
                    ofproto = datapath.ofproto
                    parser = datapath.ofproto_parser

                    for dst_edge_dpid in switch.up_group_ids.keys():
                        ecmp_group_id = switch.up_group_ids[dst_edge_dpid]
                        group_mod_msg = parser.OFPGroupMod(datapath,command = ofproto.OFPGC_ADD,
                            group_id = ecmp_group_id,type_ = ofproto.OFPGT_SELECT)
                        buckets = []
                        for port_no in switch.up_ports:
                            action = parser.OFPActionOutput(port = port_no)
                            bucket = parser.OFPBucket(weight = 10,actions = [action])
                            buckets.append(bucket)
                        group_mod_msg.buckets = buckets
                        datapath.send_msg(group_mod_msg)

        common.fat_tree['build_done'] = True
        self.logger.info("===Building fat tree topology done===")
        self.send_event_to_observers( common.EventStartScheduling() )



    @set_ev_cls(ofp_event.EventOFPPacketIn,MAIN_DISPATCHER)
    def packet_in_handler(self,ev):
        start_time = time.time()
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        dpid = datapath.id
        if ofproto.OFP_VERSION == 0x01:
            in_port = msg.in_port
        elif ofproto.OFP_VERSION >= 0x02:
            in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        eth_src_bin = haddr_to_bin(eth.src)
        eth_dst_bin = haddr_to_bin(eth.dst)
        ip_src = None
        ip_dst = None
        nw_port_src = None
        nw_port_dst = None
        nw_proto = None
        dst_dpid = None
        dst_port_no = None
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            self.logger.debug("LLDP packets are handled by topology module.")
            return

        self.mac_to_port.setdefault(dpid, {})
        switch = common.switch_list[dpid]

        if common.mac_to_switch_port.get(eth.src) is None:
            port = switch.ports[in_port]
            if port is not None and port not in switch.connected_ports:
                common.mac_to_port[eth_src_bin] = (dpid,in_port)
                port.peer = (PORT_PEER_HOST,eth.src)
            
        self.logger.info("Packet in on switch %016x" %dpid)

        if eth.ethertype == ether_types.ETH_TYPE_IP:
            ip_packet = pkt.get_protocol(ipv4.ipv4)
            ip_src = ip_packet.src
            ip_dst = ip_packet.dst
            nw_proto = ip_packet.proto

            if ip_packet.proto == in_proto.IPPROTO_TCP:
                tcp_packet = pkt.get_protocol(tcp.tcp)
                nw_port_src = tcp_packet.src_port
                nw_port_dst = tcp_packet.dst_port
                
            elif ip_packet.proto == in_proto.IPPROTO_UDP:
                udp_packet = pkt.get_protocol(udp.udp)
                nw_port_src = udp_packet.src_port
                nw_port_dst = udp_packet.dst_port
        
        if ip_src is not None and ip_dst is not None and nw_proto is not None:
            port = switch.ports[in_port]
            if port is not None and port not in switch.connected_ports:
                common.ip_to_port[ip_src] = (dpid,in_port)
            if common.ip_to_port.get(ip_dst) is not None:
                dst_dpid = common.ip_to_port[ip_dst][0]
                dst_port_no = common.ip_to_port[ip_dst][1]
        else:
            if eth_dst_bin in common.mac_to_port:
                (dst_dpid,dst_port_no) = common.mac_to_port[eth_dst_bin]
                
        do_flooding = False

        if dst_dpid is not None and dst_port_no is not None:

            if ofproto.OFP_VERSION >= 0x02:
                
                if ip_src is not None and ip_dst is not None:
                    
                    if nw_proto == in_proto.IPPROTO_TCP:
                        match = parser.OFPMatch(
                                eth_dst = eth.dst, eth_type = ether_types.ETH_TYPE_IP,
                                #ipv4_src = (ip_src,"255.255.255.255"),
                                ipv4_dst = (ip_dst,"255.255.255.255"),
                                #tcp_src = nw_port_src,
                                #tcp_dst = nw_port_dst,
                                ip_proto = in_proto.IPPROTO_TCP
                                
                            )
                    elif nw_proto == in_proto.IPPROTO_UDP:
                        match = parser.OFPMatch(
                                eth_dst = eth.dst, eth_type = ether_types.ETH_TYPE_IP,
                                #ipv4_src = (ip_src,"255.255.255.255"),
                                ipv4_dst = (ip_dst,"255.255.255.255"),
                                #udp_src = nw_port_src,
                                #udp_dst = nw_port_dst,
                                ip_proto = in_proto.IPPROTO_UDP
                               
                            )                        
                    else:
                        match = parser.OFPMatch(
                                eth_dst = eth.dst, eth_type = ether_types.ETH_TYPE_IP,
                                ipv4_dst = (ip_dst,"255.255.255.255"),
                                ip_proto = nw_proto
                            )

                else:
                    match = parser.OFPMatch(eth_dst = eth.dst, eth_type = eth.ethertype)

            elif ofproto.OFP_VERSION == 0x01:
                match = parser.OFPMatch(dl_src = eth_src_bin,dl_dst = eth_dst_bin, dl_type = eth.ethertype,
                    nw_src = ip_src, nw_dst = ip_dst, nw_proto = nw_proto
                    )
            else:
                match = None

            self.logger.info(match)
            out_port = None
            if self.topo is None:
                if dpid == dst_dpid:
                    #self.logger.info("At my switch!")
                    out_port = dst_port_no
                else:
                    next_hop = self.calc_next_hop(dpid,dst_dpid)
                    next_hop_ports = []
                    for neighbor_dpid in next_hop:
                        if common.adj[dpid][neighbor_dpid] is not None:
                            next_hop_port = common.adj[dpid][neighbor_dpid].src_port_no
                            #self.logger.info("Possible next-hop port %d" %next_hop_port)
                            next_hop_ports.append(next_hop_port)
                    if len(next_hop_ports) > 0:
                        out_port = next_hop_ports[randint(0,len(next_hop_ports) - 1)]

                if out_port is not None:
                    actions = [parser.OFPActionOutput(out_port)]
                    switch.add_flow(priority = DEFAULT_SPECIFIED_FLOW_PRIORITY,match = match, actions = actions)

            elif self.topo == 'fattree' :

                if dst_dpid == dpid:
                    #self.logger.info('same switch...')
                    
                    if ip_src is not None and ip_dst is not None and nw_proto is not None:
                    

                       match = parser.OFPMatch(
                                eth_dst = eth.dst, eth_type = ether_types.ETH_TYPE_IP
                                ,ipv4_src = (ip_src,"255.255.255.255"), ipv4_dst = (ip_dst,"255.255.255.255")
                                ,ip_proto = nw_proto
                            )
                    
                    actions = [parser.OFPActionOutput(dst_port_no)]
                    out_port = dst_port_no
                    switch.add_flow(priority = DEFAULT_SPECIFIED_FLOW_PRIORITY,match = match, actions = actions)
                else:

                    if switch in common.fat_tree['edges']:
                        #self.logger.info("Edge switch %016x" %dpid)
                        ecmp_group_id = switch.up_group_ids[dst_dpid]
                        #self.logger.info("To switch %016x, go up through group %08x" %(dst_dpid,ecmp_group_id) )

                        actions = [parser.OFPActionGroup(group_id = ecmp_group_id)]
                        up_port = switch.up_ports[ randint(0, len(switch.up_ports) - 1 ) ]
                        #actions = [parser.OFPActionOutput(up_port)]
                        out_port = up_port
                        switch.add_flow(priority = DEFAULT_SPECIFIED_FLOW_PRIORITY / 2, match = match,
                            actions = actions)

                    elif switch in common.fat_tree['aggrs']:
                        down_port = None
                        #self.logger.info("Aggregation switch %016x" %dpid)
                        if common.adj[dpid][dst_dpid] is not None:
                            down_port = common.adj[dpid][dst_dpid].src_port_no
                            
                        if down_port is None:
                            ecmp_group_id = switch.up_group_ids[dst_dpid]
                            
                            actions = [parser.OFPActionGroup(group_id = ecmp_group_id)]
                            up_port = switch.up_ports[ randint(0, len(switch.up_ports) - 1 ) ]
                            #actions = [parser.OFPActionOutput(up_port)]
                            out_port = up_port
                            switch.add_flow(priority = DEFAULT_SPECIFIED_FLOW_PRIORITY / 2, match = match,
                                actions = actions)
                        else:
                            #self.logger.info("switch %016x is connected to %016x at port %d" %(dst_dpid,dpid,down_port) )
                            actions = [parser.OFPActionOutput(down_port)]
                            out_port = down_port
                            switch.add_flow( priority = DEFAULT_SPECIFIED_FLOW_PRIORITY, match = match,
                                actions = actions)
                    elif switch in common.fat_tree['cores']:
                        down_port = None
                        down_aggr_dpid = None
                        #self.logger.info("Check %d aggregation switches under core %016x" %(len(common.adj[dpid]), dpid ) )
                        for aggr_dpid in common.adj[dpid]:
                            if common.adj[dpid][aggr_dpid] is not None:
                                port_no = common.adj[dpid][aggr_dpid].src_port_no
                                if common.adj[aggr_dpid][dst_dpid] is not None:
                                    down_port = port_no
                                    down_aggr_dpid = aggr_dpid
                                    break

                        #self.logger.info("Core switch %016x to switch %016x through port %d, aggregation switch %016x"
                        # %(dpid,dst_dpid,down_port,down_aggr_dpid) )
                        actions = [parser.OFPActionOutput(down_port)]
                        out_port = down_port
                        switch.add_flow(priority = DEFAULT_SPECIFIED_FLOW_PRIORITY, match = match,actions = actions)

                    else:
                        #self.logger.info("This switch %016x not in our tree." %dpid)
                        pass
            
            if out_port is not None:
                data = msg.data
                actions = [parser.OFPActionOutput(out_port)]
                dst_switch = common.switch_list[dst_dpid]
                packet_out_msg = parser.OFPPacketOut(datapath = datapath, buffer_id = ofproto.OFP_NO_BUFFER,in_port = in_port,
                    actions = actions, data = data)
                datapath.send_msg(packet_out_msg)

        else:
            do_flooding = True

        if do_flooding:
            #DO FLOODING.
            data = None
            if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                data = msg.data
            if ofproto.OFP_VERSION == 0x01 or len(common.switch_list) == 1:
                actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
                packet_out_msg = parser.OFPPacketOut(datapath = datapath, buffer_id = msg.buffer_id,in_port = in_port,
                    actions = actions, data = data)
                datapath.send_msg(packet_out_msg)

            elif ofproto.OFP_VERSION >= 0x02:
                switch = common.switch_list[dpid]
                if switch.flood_group_id is not None:
                    actions = [parser.OFPActionGroup(group_id = switch.flood_group_id)]
                    packet_out_msg = parser.OFPPacketOut(datapath = datapath, buffer_id = msg.buffer_id, in_port = in_port,
                        actions = actions, data = data)
                    datapath.send_msg(packet_out_msg)


    @set_ev_cls(topo_event.EventSwitchEnter)
    def switch_enter_handler(self,ev):
        self.logger.info("Switch Enters %s" %ev.switch)

        switch = common.Switch(ev.switch.dp,ev.switch.ports)
        common.switch_list[switch.datapath.id] = switch
        for port in ev.switch.ports:
            common.mac_to_switch_port[port.hw_addr] = (switch.datapath.id,port.port_no)

        #Install table-miss entry
        ofproto = switch.datapath.ofproto
        parser = switch.datapath.ofproto_parser

        self.logger.info("Switch %016x use protocol %d" %(switch.datapath.id,ofproto.OFP_VERSION) )

        if ofproto.OFP_VERSION >= 0x02:
            match = parser.OFPMatch()
            actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,ofproto.OFPCML_NO_BUFFER)]
            switch.add_flow( actions = actions, match = match,
                idle_timeout = 0, hard_timeout = 0,priority = 0)

        #DROP all DHCP packets.
        match = None
        if ofproto.OFP_VERSION >= 0x02:
            match = parser.OFPMatch(eth_type = ether_types.ETH_TYPE_IP, ip_proto = in_proto.IPPROTO_UDP,
                udp_src = 68, udp_dst = 67
                )
        elif ofproto.OFP_VERSION == 0x01:
            match = parser.OFPMatch(dl_type = ether_types.ETH_TYPE_IP, nw_proto = in_proto.IPPROTO_UDP,
                nw_src = 68, nw_dst = 67)

        if match is not None:
            switch.add_flow(priority = 65000, match = match, actions = [], idle_timeout = 0)

        self.logger.info("Now %d switches" %len(common.switch_list) )

        if len(common.switch_list) >= 2:
            self.spanning_tree_done = False

        if self.topo == 'fattree':
            if len(common.switch_list) > self.fat_tree_k * self.fat_tree_k * 5 / 4:
                self.fat_tree_k += 2
                k = self.fat_tree_k
                self.expected_links = k * k * k

    
    @set_ev_cls(topo_event.EventSwitchLeave)
    def switch_leave_handler(self,ev):
        self.logger.info("Switch %s leaves" %ev.switch)
        self.do_schedule = False
        switches = topo_api.get_switch(self)
        self.logger.info("Now %d switches: " %len(switches) )

        if len(switches) > 0:
            for switch in switches:
                self.logger.info("Switch %016x" %switch.dp.id)
                self.logger.info(switch)

        switch_leave = common.switch_list[ev.switch.dp.id]
        if switch_leave is not None:
            self.logger.info("Remove switch %016x from my switch list" %switch_leave.datapath.id)
            del common.switch_list[ev.switch.dp.id]

    @set_ev_cls(topo_event.EventLinkAdd)
    def link_add_handler(self,ev):
        link = ev.link
        
        src_dpid = link.src.dpid
        src_port_no = link.src.port_no
        dst_dpid = link.dst.dpid
        dst_port_no = link.dst.port_no

        if common.adj[src_dpid][dst_dpid] is None:
            self.logger.info("Add link : %016x:%s-->%016x:%s" %(src_dpid,src_port_no,dst_dpid,dst_port_no) )
            of_link = common.OpenFlowLink(src_dpid,src_port_no,dst_dpid,dst_port_no)
            src_switch = common.switch_list[src_dpid]
            dst_switch = common.switch_list[dst_dpid]
            self.total_links += 1
            if src_switch is not None:
                if src_switch.ports[src_port_no] is not None:
                    port = src_switch.ports[src_port_no]
                    src_switch.connected_ports.add(port)
                    if len(src_switch.connected_ports)  == len(src_switch.ports):
                        self.logger.info("All ports connected on switch %016x. This is not edge." %src_switch.datapath.id)
                        src_switch.possible_edge = False
                    port.disable_flood()

            if dst_switch is not None:
                if dst_switch.ports[dst_port_no] is not None:
                    port = dst_switch.ports[dst_port_no]
                    dst_switch.connected_ports.add(port)
                    if len(dst_switch.connected_ports)  ==  len(dst_switch.ports):
                        self.logger.info("All ports connected on switch %016x. This is not edge." %dst_switch.datapath.id)
                        dst_switch.possible_edge = False
                    port.disable_flood()

            common.adj[src_dpid][dst_dpid] = of_link

            src_switch = common.switch_list[src_dpid]
            if src_switch is not None:
                src_switch.ports[src_port_no].peer = (PORT_PEER_SWITCH,(dst_dpid,dst_port_no) )

            if common.adj[dst_dpid][src_dpid] is not None:
                #self.logger.info("Both side connected. ")
                if not self.spanning_tree_done:
                    tree_links = self.calc_spanning_tree()
                    if tree_links is not None:
                        for dpid in common.switch_list.keys():
                            common.switch_list[dpid].set_flood_group()

            if self.install_port_events and dst_dpid > src_dpid:
                #self.logger.info("Install event on switch %016x port %d" %(src_dpid,src_port_no))
                ofp_version = src_switch.datapath.ofproto.OFP_VERSION
                if ofp_version == 0x04:
                    port_event_req = evt_13.OFP13EventRequestPortTimer(
                        datapath = src_switch.datapath, request_type = evt_13.EVT_REQUEST_TYPE_ADD,
                        event_periodic = evt_13.EVT_PERIODIC, port_no = src_port_no,
                        event_conditions = (evt_13.EVT_EVENT_CONDITION_TX_BYTES | evt_13.EVT_EVENT_CONDITION_RX_BYTES)
                        , interval_sec = 1, interval_msec = 0,
                        threshold_tx_bytes = 10 * 1000 * 1000 / 8, threshold_rx_bytes = 10 * 1000 * 1000 / 8)
                    src_switch.datapath.send_msg(port_event_req)

                elif ofp_version == 0x01:
                    port_event_req = evt_10.OFP10EventRequestPortTimer(
                        datapath = src_switch.datapath, request_type = evt_10.EVT_REQUEST_TYPE_ADD,
                        event_periodic = evt_10.EVT_PERIODIC, port_no = src_port_no,
                        event_conditions = (evt_10.EVT_EVENT_CONDITION_TX_BYTES | evt_10.EVT_EVENT_CONDITION_RX_BYTES)
                        , interval_sec = 1, interval_msec = 0,
                        threshold_tx_bytes = 10 * 1000 * 1000 / 8, threshold_rx_bytes = 10 * 1000 * 1000 / 8)
                    src_switch.datapath.send_msg(port_event_req)

            if self.topo == 'fattree':
                if self.total_links == self.expected_links:
                    self.build_fat_tree_topo()


    @set_ev_cls(topo_event.EventLinkDelete)
    def link_delete_handler(self,ev):
        pass
        

    @set_ev_cls(topo_event.EventPortAdd)
    def port_add_handler(self,ev):
        port = ev.port
        self.logger.info("Add port %s of type %s" %(port,type(port) ) )

    @set_ev_cls(topo_event.EventPortDelete)
    def port_delete_handler(self,ev):
        port = ev.port
        self.logger.info("Delete port %s of type %s" %(port,type(port) ) )


    @set_ev_cls(topo_event.EventPortModify)
    def port_modify_handler(self,ev):
        port = ev.port
        self.logger.info("Port modified: %s" %port)

    @set_ev_cls(evt_13.EventSwitchEventReply)
    def switch_event_reply_handler_ofp13(self,ev):
        pass

    @set_ev_cls(evt_13.EventSwitchEventReport)
    def switch_event_report_handler_ofp13(self,ev):
        #self.logger.info("Event report:")
        report = ev.msg
        datapath = report.datapath
        switch = common.switch_list[datapath.id]
        if report.event_type == evt_13.EVT_PORT_STATS_TIMER_TRIGGER and switch is not None:
            port_no = report.port_no
            port = switch.ports.get(port_no)
            if port is not None:
                peer = port.peer
                if peer is not None and peer[0] == PORT_PEER_SWITCH:
                    dpid = datapath.id
                    peer_dpid = peer[1][0]
                    link = common.adj[dpid][peer_dpid]
                    rev_link = common.adj[peer_dpid][dpid]
                    if link is not None:
                        rate = report.new_tx_bytes * 8 / ( report.interval_sec + report.interval_msec / 1000.0)
                        rev_rate = report.new_rx_bytes * 8 / (report.interval_sec + report.interval_msec / 1000.0)
                        link.set_rate(rate)
                        if rev_link is not None:
                            rev_link.set_rate(rev_rate)

                        self.logger.info("Rate at link %016x --> %016x has been updated to %.0f bps" %(dpid,peer_dpid,rate) )
                        self.logger.info("Rate at link %016x --> %016x has been updated to %.0f bps" %(peer_dpid,dpid,rev_rate) )
                        self.link_rate_out_file.write("Push: %s+%.0f %016x %016x %.0fbps %dbytes in total\n" 
                            %(time.strftime("%Y%m%d %H:%M:%S"),time.time() % 1 * 1000,dpid,peer_dpid,rate,report.total_tx_bytes ) )
                        self.link_rate_out_file.write("Push: %s+%.0f %016x %016x %.0fbps %dbytes in total\n" 
                            %(time.strftime("%Y%m%d %H:%M:%S"),time.time() % 1 * 1000,peer_dpid,dpid,rev_rate,report.total_rx_bytes ) )
                        self.link_rate_out_file.flush()


    def calc_fattree_ecmp_group(self):
        LINK_CAPACITY = 1000 * 1000 * 1000 
        self.logger.info("WTF")

        if self.topo != 'fattree':
            return

        for src_edge_switch in common.fat_tree['edges']:
            for dst_edge_switch in common.fat_tree['edges']:
                paths = []
                if src_edge_switch == dst_edge_switch:
                    continue

                paths = self.calc_fat_tree_all_paths(src_edge_switch.datapath.id,dst_edge_switch.datapath.id)
                for path in paths:
                    rate_max = 0.0
                    avg_rate = 0.0
                    for link in path:
                        if link.rate_update_time <= time.time() - 2.0:
                            link.rate = 0.0
                            link.rate_update_time = time.time()
                        rate = link.rate
                        if rate / LINK_CAPACITY >= rate_max:
                            rate_max = rate / LINK_CAPACITY
                        avg_rate += rate / LINK_CAPACITY
                    if rate_max >= 0.1:
                        self.logger.info("path %s: congestion rate(MAX) = %.2f%%" %(path,rate_max * 100))
                        self.logger.info("congestion rate(AVG) = %.2f%%" %(avg_rate / len(path) * 100 ) )
                    else:
                        self.logger.info("path %s is idle enough." %path )

      
    def send_port_stats_requests(self):
        for u in common.adj:
            switch = common.switch_list.get(u)
            if switch is not None:
                datapath = switch.datapath
                parser = datapath.ofproto_parser
                ofproto = datapath.ofproto
                for v in common.adj[u]:
                    if u < v and common.adj[u][v] is not None:
                        port_no = common.adj[u][v].src_port_no
                        port_stats_req = parser.OFPPortStatsRequest(datapath,0,port_no)
                        datapath.send_msg(port_stats_req)


    @set_ev_cls(ofp_event.EventOFPPortStatsReply)
    def port_stats_handler(self,ev):
        datapath = ev.msg.datapath
        dpid = datapath.id
        switch = common.switch_list[dpid]
        if switch is not None:
            for stat in ev.msg.body:
                port_no = stat.port_no
                port = switch.ports.get(port_no)
                if port is not None and port.peer is not None and port.peer[0] == PORT_PEER_SWITCH:
                    peer_dpid = port.peer[1][0]
                    link = common.adj[dpid][peer_dpid]
                    rev_link = common.adj[peer_dpid][dpid]
                    delta_tx_bytes = stat.tx_bytes - port.tx_bytes
                    delta_rx_bytes = stat.rx_bytes - port.rx_bytes
                    delta_time = time.time() - port.stats_update_time 
                    self.logger.info("Switch %016x port %d" %(dpid,port_no))
                    self.logger.info("New : TX = %d bytes, RX = %d bytes" %(delta_tx_bytes,delta_rx_bytes) )
                    self.logger.info("Total: TX = %d bytes, RX = %d bytes" %(stat.tx_bytes,stat.rx_bytes) )
                    link.set_rate( delta_tx_bytes / delta_time)
                    if rev_link is not None:
                        rev_link.set_rate(delta_rx_bytes / delta_time)

                    port.update_stats(stat.tx_packets,stat.tx_bytes,stat.rx_packets,stat.rx_bytes)

                    self.link_rate_out_file.write("Polling: %s+%.0f %016x %016x %.0fbps %dbytes in total\n" 
                        %(time.strftime("%Y%m%d %H:%M:%S"),time.time() % 1 * 1000,dpid,peer_dpid, delta_tx_bytes * 8 / delta_time, stat.tx_bytes ) )
                    self.link_rate_out_file.write("Polling: %s+%.0f %016x %016x %.0fbps %dbytes in total\n" 
                        %(time.strftime("%Y%m%d %H:%M:%S"), time.time() % 1 * 1000 ,peer_dpid,dpid, delta_rx_bytes * 8/ delta_time, stat.rx_bytes) )


    def send_port_req_loop(self,send_interval = 1.0):
        while self.poll_port_stats:
            self.send_port_stats_requests()
            time.sleep(send_interval)