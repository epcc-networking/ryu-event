import os
import time
import logging

from collections import defaultdict,namedtuple

from ryu.controller import event,ofp_event

DEFAULT_PRIORITY = 32768

EPCC_EXPERIENTER_ID = 0xEBCC3118

PORT_PEER_HOST = 0
PORT_PEER_SWITCH = 1
PORT_PEER_CONTROLLER = 2

PATH_CHOOSE_RANDOM = 'random'
PATH_CHOOSE_HASH = 'hash'
PATH_CHOOSE_FIRST_FIT = 'first fit'

RATE_1Gbps = 1000 * 1000 * 1000
ELEPHANT_BYTE_RATE_THRESHOLD = 1000 * 1000 * 1000 / (10 * 8)

LOG = logging.getLogger('common things')

adj = defaultdict(lambda : defaultdict(lambda: None) )
switch_list = {}
ip_to_port = {}
mac_to_port = {}
mac_to_switch_port = {}

layered_topo = []
fat_tree = {'edges':set([]),'aggrs':set([]),'cores':set([]),'build_done':False}

registered_elephants = defaultdict(lambda:None)


class EventElephantDetectRequest(event.EventBase):
    def __init__(self,datapath):
        super(EventElephantDetectRequest,self).__init__()
        self.datapath = datapath

class EventStartScheduling(event.EventBase):
    def __init__(self):
        super(EventStartScheduling,self).__init__()

class EventPauseScheduling(event.EventBase):
    def __init__(self):
        super(EventPauseScheduling,self).__init__()

class EventStopScheduling(event.EventBase):
    def __init__(self):
        super(EventStopScheduling,self).__init__()

class OpenFlowLink(object):
    def __init__(self,src_dpid,src_port_no,dst_dpid,dst_port_no):
        self.src_dpid = src_dpid
        self.src_port_no = src_port_no
        self.dst_dpid = dst_dpid
        self.dst_port_no = dst_port_no
        self.rate = 0
        self.rate_update_time = time.time()

        self.reserved_bw = 0

    def __str__(self):
        return "Link [%016x:%d]-->[%016x:%d]\n" %(self.src_dpid,self.src_port_no,self.dst_dpid,self.dst_port_no)

    def __repr__(self):
        return self.__str__()
    
    def set_rate(self,rate):
        self.rate = rate
        self.rate_update_time = time.time()

class OpenFlowPort(object):
    def __init__(self,switch,port_no,hw_addr,live= True,peer = None):
        self.switch = switch
        self.port_no = port_no
        self.hw_addr = hw_addr
        self.live = live
        self.peer = peer

        self.flood_enabled = True

        self.tx_packets = 0
        self.tx_bytes = 0
        self.rx_packets = 0
        self.rx_bytes = 0
        self.stats_update_time = time.time()

    def enable_flood(self):
        if not self.flood_enabled:
            self.flood_enabled = True

            if self.switch.datapath.ofproto.OFP_VERSION == 0x01:
                datapath = self.switch.datapath
                ofproto = datapath.ofproto
                parser = datapath.ofproto_parser

                port_mod_msg = parser.OFPPortMod(datapath = datapath, port_no = self.port_no, hw_addr = self.hw_addr,
                    mask = ofproto.OFPPC_NO_FLOOD, config = 0)
                datapath.send_msg(port_mod_msg)

    def disable_flood(self):
        if self.flood_enabled:
            self.flood_enabled = False

            if self.switch.datapath.ofproto.OFP_VERSION == 0x01:
                datapath = self.switch.datapath
                ofproto = datapath.ofproto
                parser = datapath.ofproto_parser

                port_mod_msg = parser.OFPPortMod(datapath = datapath, port_no = self.port_no, hw_addr = self.hw_addr,
                    mask = ofproto.OFPPC_NO_FLOOD, config = ofproto.OFPPC_NO_FLOOD)
                datapath.send_msg(port_mod_msg)

    def update_stats(self,tx_packets = None, tx_bytes = None, rx_packets = None,rx_bytes = None):
        self.tx_packets = tx_packets
        self.tx_bytes = tx_bytes
        self.rx_packets = rx_packets
        self.rx_bytes = rx_bytes
        self.stats_update_time = time.time()


class InstalledFlow(object):
    def __init__(self,match,actions,priority,timeout = 10):
        self.match = match
        self.actions = actions
        self.timeout = timeout
        self.priority = priority
        self.install_time = time.time()

    def is_timeout(self):
        if time.time() > self.install_time + self.timeout:
            return True
        else:
            return False

def get_ip_pair(match,ofp_version):
    ip_src = None
    ip_dst = None
    ip_proto = None
    if ofp_version == 0x01:
        ip_src = match.nw_src
        ip_dst = match.nw_dst
        ip_proto = match.ip_proto
    elif ofp_version >= 0x02:
        ip_src = match.get('ipv4_src')
        ip_dst = match.get('ipv4_dst')
        ip_proto = match.get('ip_proto')


    return (ip_src,ip_dst,ip_proto)

def get_flow_5tuple(match,ofp_version):
    ip_src = None
    ip_dst = None
    ip_proto = None
    tp_port_src = None
    tp_port_dst = None
    if ofp_version == 0x01:
        ip_src = match.nw_src
        ip_dst = match.nw_dst
        ip_proto = match.ip_proto
        tp_port_src = match.tp_src
        tp_port_dst = match.tp_port_dst
    elif ofp_version >= 0x02:
        ip_src = match.get('ipv4_src')
        ip_dst = match.get('ipv4_dst')
        ip_proto = match.get('ip_proto')
        if ip_proto == 6: #TCP
            tp_port_src = match.get('tcp_src')
            tp_port_dst = match.get('tcp_dst')
        if ip_proto == 17: #UDP
            tp_port_src = match.get('udp_src')
            tp_port_dst = match.get('udp_dst')

    return (ip_src,ip_dst,tp_port_src,tp_port_dst,ip_proto)

class FlowRecord(object):
    def __init__(self,match,ofp_version,reporter_dpid ,matched_packets = 0,matched_bytes = 0,duration = 0.0):
        self.match = match
        self.ofp_version = ofp_version
        self.reporter_dpid = reporter_dpid
        self.packets_when_caught = matched_packets
        self.bytes_when_caught = matched_bytes
        self.matched_packets = matched_packets
        self.matched_bytes = matched_bytes
        self.caught_time = time.time()
        self.update_time = time.time()
        self.duration = duration
        #following members are for scheduling only...
        self.assigned = False
        self.same_pod = False
        self.assigned_aggr_dpid = None
        self.assigned_core_dpid = None 
        self.active = True
        self.bw_demand = None

        self.flow_ip_pair = get_ip_pair(match,ofp_version)

    def update_stats(self,matched_packets,matched_bytes,duration):
        self.matched_packets = matched_packets
        self.matched_bytes = matched_bytes
        self.duration = duration
        self.update_time = time.time()
        self.is_active = True

class Switch (object):
    def __init__(self,datapath,ports):
        self.datapath = datapath
        self.ports = defaultdict(lambda:None)
        self.connected_ports = set([])

        self.up_time = time.time()
        self.leave_time = None

        self.flood_group_id = None

        self.layer = None
        self.possible_edge = True
        self.is_edge = False

        self.up_ports = []
        self.up_group_ids = defaultdict(lambda:None)
        self.dpid_to_port = defaultdict(lambda:[])


        self.installed_flows = []


        for port in ports:
            port_no = port.port_no
            hw_addr = port.hw_addr
            self.ports[port_no] = OpenFlowPort(self,port_no,hw_addr)

    def set_flood_group(self):
        if self.datapath.ofproto.OFP_VERSION >= 0x02:
            datapath = self.datapath
            ofproto = self.datapath.ofproto
            parser = self.datapath.ofproto_parser
            flood_group_id = 0xf100d
            if self.flood_group_id is None:
                self.flood_group_id = flood_group_id
                group_mod_command = ofproto.OFPGC_ADD
            else:
                group_mod_command = ofproto.OFPGC_MODIFY

            buckets = []
            for port_no in self.ports:
                port = self.ports[port_no]
                if port_no <= ofproto.OFPP_MAX and port.flood_enabled:
                    action_output = [parser.OFPActionOutput(port = port.port_no)]
                    bucket = parser.OFPBucket(actions = action_output)
                    buckets.append(bucket)

            group_mod_msg = parser.OFPGroupMod(datapath = datapath, command = group_mod_command,
                type_ = ofproto.OFPGT_ALL, group_id = self.flood_group_id, buckets = buckets)
            datapath.send_msg(group_mod_msg)

    def add_flow(self,match,actions,buffer_id = None,priority = DEFAULT_PRIORITY
                ,idle_timeout = 10, hard_timeout = 0, send_flow_removed = True):

        datapath =  self.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        #start_time = time.time()
        #installed_flow = InstalledFlow(match,actions,priority,idle_timeout)
        #self.installed_flows.append(installed_flow)

        #LOG.info("Add flow on switch %016x starting at %.6f" %(datapath.id,start_time) )

        flags = 0
        if send_flow_removed:
            flags = flags | ofproto.OFPFF_SEND_FLOW_REM

        if buffer_id is None:
            buffer_id = ofproto.OFP_NO_BUFFER

        flow_mod_msg = None
        if ofproto.OFP_VERSION == 0x01:
            flow_mod_msg = parser.OFPFlowMod(datapath = datapath,priority = priority,match = match, actions = actions,
            command = ofproto.OFPFC_ADD,idle_timeout = idle_timeout, hard_timeout = hard_timeout,
            buffer_id = buffer_id, flags = flags)
        elif ofproto.OFP_VERSION >= 0x02:
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions)]
            flow_mod_msg = parser.OFPFlowMod(datapath = datapath, priority = priority, match = match, instructions = inst
                , command = ofproto.OFPFC_ADD, idle_timeout = idle_timeout, hard_timeout = hard_timeout
                , buffer_id = buffer_id, flags = flags)
        else:
            LOG.err("Switch %016x has unknown version: %d" %(datapath.id,ofproto.OFP_VERSION))

        if isinstance(flow_mod_msg,parser.OFPFlowMod):
            datapath.send_msg(flow_mod_msg)

        #LOG.info("Adding flow on switch %016x finished, cost time %.6f(%.6f--%.6f)" 
        #    %(datapath.id, time.time() - start_time, start_time, time.time() ) )









