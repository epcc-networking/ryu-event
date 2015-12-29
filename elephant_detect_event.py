import os
import time
import logging

from collections import defaultdict

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls

import ryu.ofproto
from ryu.lib.packet import packet,ethernet,ether_types
from ryu.lib.packet import lldp,arp,ipv4,tcp,udp,in_proto
from ryu.lib import hub

import event_message_ofp10 as evt_10
import event_message_ofp13 as evt_13

import common

class EventElephantDetector(app_manager.RyuApp):
    OFP_VERSIONS = [ryu.ofproto.ofproto_v1_0.OFP_VERSION,
        ryu.ofproto.ofproto_v1_3.OFP_VERSION]
    def __init__(self,out_file="detect_event.out"):
        super(EventElephantDetector,self).__init__()
        #self.registered_elephants = defaultdict(lambda:None)
        self.name = "Event based elephant detector"
        self.out_file = open(out_file,"w+")
        self.out_file.write("Start elephant flow detection on time %s\n" %time.strftime("%Y-%m-%d %H:%M:%S") )
        self.out_file.flush()
        self.total_flows = 0
        self.elephant_flows = 0
        self.start_time = None

    @set_ev_cls(common.EventElephantDetectRequest,MAIN_DISPATCHER)
    def elephant_detect_req_handler(self,ev):
        datapath = ev.datapath
        ofproto = ev.datapath.ofproto
        parser = ev.datapath.ofproto_parser
        if self.start_time is None:
            self.start_time = time.time()
        self.out_file.write("Detect elephant flows on switch %016x\n" %datapath.id)
        self.out_file.flush()
        if ofproto.OFP_VERSION == ryu.ofproto.ofproto_v1_0.OFP_VERSION:
            event_req = evt_10.OFP10EventRequestFlowTimer(datapath,request_type = evt_10.EVT_REQUEST_TYPE_ADD,
                event_periodic = evt_10.EVT_PERIODI,interval_sec = 1,interval_msec = 0,
                event_conditions = evt_10.EVT_EVENT_CONDITION_NEW_MATCH_BYTES, 
                threshold_new_match_bytes = common.ELEPHANT_BYTE_RATE_THRESHOLD * 1)
            match = parser.OFPMatch()
            match.dl_type = ether_types.ETH_TYPE_IP
            event_req.match = match
            datapath.send_msg(event_req)

        elif ofproto.OFP_VERSION == ryu.ofproto.ofproto_v1_3.OFP_VERSION:
            event_req = evt_13.OFP13EventRequestFlowTimer(datapath,request_type = evt_13.EVT_REQUEST_TYPE_ADD,
                event_periodic = evt_13.EVT_PERIODIC,interval_sec = 1,interval_msec = 0,
                 event_conditions = evt_13.EVT_EVENT_CONDITION_NEW_MATCH_BYTES, 
                 threshold_new_match_bytes = common.ELEPHANT_BYTE_RATE_THRESHOLD )
            
            match = parser.OFPMatch(eth_type = ether_types.ETH_TYPE_IP)
            
            event_req.match = match
            datapath.send_msg(event_req)

    @set_ev_cls(evt_13.EventSwitchEventReport)
    def switch_event_report_handler(self,ev):
        datapath = ev.msg.datapath
        report = ev.msg
        
        if report.event_type == evt_13.EVT_FLOW_STATS_TIMER_TRIGGER:
            self.out_file.write("Event ID %d Reported from switch %016x at time %.3f\n" %(report.event_id,datapath.id, time.time()-self.start_time ) )

            match = report.match
            self.out_file.write("%d flows reported\n" %len(report.single_flows))
            for single_flow in report.single_flows:
                flow_duration = single_flow.duration_sec + single_flow.duration_nsec * 1e-9
                self.out_file.write("Flow %s\n" %single_flow.match)
                self.out_file.write("New matched: %d/%d packets, %d/%d bytes\n" 
                    %(single_flow.new_match_packets,single_flow.total_match_packets,single_flow.new_match_bytes,single_flow.total_match_bytes))
                flow_ip_pair = common.get_ip_pair(single_flow.match,datapath.ofproto.OFP_VERSION)
                flow_5tuple = common.get_flow_5tuple(single_flow.match,datapath.ofproto.OFP_VERSION)
                #self.out_file.write("%s %s %s\n" %(flow_ip_pair[0],flow_ip_pair[1],flow_ip_pair[2]) )
                #if None not in flow_ip_pair:
                if flow_5tuple[0] is not None and flow_5tuple[1] is not None:
                    hash_val = hash(flow_5tuple)
                    record = common.registered_elephants[hash_val]
                    duration = single_flow.duration_sec + single_flow.duration_nsec * 1e-9
                    if record is None:
                        record = common.FlowRecord(single_flow.match, datapath.ofproto.OFP_VERSION,
                            single_flow.total_match_packets, single_flow.total_match_bytes,duration)
                        self.out_file.write("Elephant caught when %d bytes matched\n" %single_flow.total_match_bytes)
                        common.registered_elephants[hash_val] = record
                    else:
                        record.update_stats(single_flow.total_match_packets,single_flow.total_match_bytes,duration)
                else:
                    #self.out_file.write("IP pair not complete.\n" )
                    pass
            self.out_file.flush()

    
    @set_ev_cls(ofp_event.EventOFPFlowRemoved)
    def flow_removed_handler(self,ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        #self.logger.info("Flow removed, match %s" %ev.msg.match)
        flow_ip_pair = common.get_ip_pair(ev.msg.match,ofproto.OFP_VERSION)
        flow_5tuple = common.get_flow_5tuple(ev.msg.match,ofproto.OFP_VERSION)
        #if None not in flow_ip_pair:
        if flow_5tuple[0] is not None and flow_5tuple[1] is not None:
            self.total_flows += 1
            if ev.msg.byte_count >= 1000 * 1000 * 100 / 8:
                self.elephant_flows += 1
                hash_val = hash(flow_5tuple)
                record = common.registered_elephants.get(hash_val)
                if record is not None:
                    self.out_file.write("Flow %s caught when %d/%d bytes transfered.\n" %(ev.msg.match,record.bytes_when_caught,ev.msg.byte_count) )
                    #del common.registered_elephants[hash_val]
                self.out_file.write("Transfered %d packets %d bytes in %.3f seconds life\n" 
                    %(ev.msg.packet_count,ev.msg.byte_count,(ev.msg.duration_sec+ev.msg.duration_sec * 1e-9 ) ) )

            self.out_file.write("%d flows removed since start, %d are elephant flows\n" %(self.total_flows,self.elephant_flows))
    


            