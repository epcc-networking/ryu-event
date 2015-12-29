import os
import time
import logging

import struct

from ryu.base import app_manager
from ryu.controller import event,ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls

import ryu.ofproto.ofproto_v1_3 as ofproto
import ryu.ofproto.ofproto_v1_3_parser as ofproto_parser

from event_message_common import *
from ryu import utils
from ryu.lib.pack_utils import msg_pack_into

UINT64_MAX = 0xffFFffFFffFFffFF

LOG = logging.getLogger('ryu.epcc.event_msg_ofp13')

class OFP13EpccEventHeader(ofproto_parser.OFPExperimenter):


    def __init__(self,datapath,subtype,data = None):
        super(OFP13EpccEventHeader,self).__init__(datapath,EPCC_EXPERIMENTER_ID,subtype,data)


class OFP13EpccEventRequest(OFP13EpccEventHeader):
    def __init__(self,datapath,request_type = None,event_periodic = None,event_type = None,event_id = 0):
        super(OFP13EpccEventRequest,self).__init__(datapath,EVT_SUBTYPE_EVENT_REQUEST)
        self.request_type = request_type
        self.event_periodic = event_periodic
        self.event_type = event_type
        self.event_id = event_id
        self.data = bytearray()

    def serialize_req_header(self):
        msg_pack_into(EVT_REQUEST_HEADER_FORMAT_STR,self.data,0,
            self.request_type,self.event_periodic,self.event_type,self.event_id)



class OFP13EventRequestPortTimer(OFP13EpccEventRequest):
    def __init__(self,datapath,request_type = None,event_periodic = None,event_id = 0,
        port_no = None, event_conditions = 0, interval_sec = 0, interval_msec = 0,
        threshold_tx_packets = UINT64_MAX, threshold_tx_bytes = UINT64_MAX,
        threshold_rx_packets = UINT64_MAX, threshold_rx_bytes = UINT64_MAX 
        ):
        super(OFP13EventRequestPortTimer,self).__init__(datapath,request_type,event_periodic
            ,EVT_PORT_STATS_TIMER_TRIGGER,event_id)
        self.port_no = port_no
        self.interval_sec = interval_sec
        self.interval_msec = interval_msec
        self.event_conditions = event_conditions
        self.threshold_tx_packets = threshold_tx_packets
        self.threshold_tx_bytes = threshold_tx_bytes
        self.threshold_rx_packets = threshold_rx_packets
        self.threshold_rx_bytes = threshold_rx_bytes

    def _serialize_body(self):
        self.serialize_req_header()
        offset = EVT_REQUEST_HEADER_SIZE
        msg_pack_into(EVT_PORT_TIMER_REQUEST_PACK_STR,self.data,offset,
            self.port_no,self.event_conditions,self.interval_sec,self.interval_msec,
            self.threshold_tx_packets,self.threshold_tx_bytes,self.threshold_rx_packets,self.threshold_rx_bytes)
        #self.buf += self.data

        ofproto_parser.OFPExperimenter._serialize_body(self)

OFP13_FLOW_REQUEST_PACK_STR = "!H2xIIQQQQB3xIIQQ"

class OFP13EventRequestFlowTimer(OFP13EpccEventRequest):
    def __init__(self,datapath,request_type = None,event_periodic = None, event_id = 0,
        table_id = 0xff, out_port = ofproto.OFPP_ANY, out_group = ofproto.OFPG_ANY,
        match = None, flow_cookie = 0, cookie_mask = 0, 
        interval_sec = 0, interval_msec = 0, event_conditions = 0,
        threshold_new_match_packets = UINT64_MAX, threshold_new_match_bytes = UINT64_MAX,
        threshold_total_match_packets = UINT64_MAX, threshold_total_match_bytes = UINT64_MAX
        ):
        super(OFP13EventRequestFlowTimer,self).__init__(datapath,request_type,event_periodic,
            EVT_FLOW_STATS_TIMER_TRIGGER,event_id)
        self.table_id = table_id
        self.out_port = out_port
        self.out_group = out_group
        if match is None:
            match = ofproto_parser.OFPMatch()
        assert isinstance(match,ofproto_parser.OFPMatch)
        self.match = match
        self.flow_cookie = flow_cookie
        self.cookie_mask = cookie_mask
        self.interval_sec = interval_sec
        self.interval_msec = interval_msec
        self.event_conditions = event_conditions
        self.interval_sec = interval_sec
        self.interval_msec = interval_msec
        self.event_conditions = event_conditions
        self.threshold_new_match_packets = threshold_new_match_packets
        self.threshold_new_match_bytes = threshold_new_match_bytes
        self.threshold_total_match_packets = threshold_total_match_packets
        self.threshold_total_match_bytes = threshold_total_match_bytes
        self.data = bytearray()

    def _serialize_body(self):
        self.serialize_req_header()
        offset = EVT_REQUEST_HEADER_SIZE
        msg_pack_into(OFP13_FLOW_REQUEST_PACK_STR,self.data,offset,
            self.event_conditions,self.interval_sec,self.interval_msec,
            self.threshold_new_match_packets,self.threshold_new_match_bytes,
            self.threshold_total_match_packets,self.threshold_total_match_bytes,
            self.table_id,self.out_port,self.out_group,self.flow_cookie,self.cookie_mask
            )
        offset += 72
        
        self.match.serialize(self.data,offset)
        ofproto_parser.OFPExperimenter._serialize_body(self)

class OFP13EpccEventReply(OFP13EpccEventHeader):
    def __init__(self,datapath,event_status,event_type,event_id):
        super(OFP13EpccEventReply,self).__init__(datapath,EVT_SUBTYPE_EVENT_REPLY)
        self.event_status = event_status
        self.event_type = event_type
        self.event_id = event_id

    @classmethod
    def parser(cls,datapath,buf,offset):
        (event_status,event_type,event_id) = struct.unpack_from(
            EVT_EVENT_REPLY_PACK_STR,buf,offset)
        return cls(datapath,event_status,event_type,event_id)

class OFP13EpccEventReport(OFP13EpccEventHeader):
    _REPORT_EVENT_TYPES = {}
    @staticmethod
    def register_report_event_type(event_type):
        def _register_report_event_type(cls):
            cls.cls_event_type = event_type
            OFP13EpccEventReport._REPORT_EVENT_TYPES[event_type] = cls
            return cls
        return _register_report_event_type

    def __init__(self,datapath,report_reason,event_type,event_id,data = None):
        super(OFP13EpccEventReport,self).__init__(datapath,EVT_SUBTYPE_EVENT_REPORT)
        self.report_reason = report_reason
        self.event_type = event_type
        self.event_id = event_id

    @classmethod
    def parser(cls,datapath,buf,offset):
        start_time = time.time()
        #LOG.info("Start parsing event report at %.6f" %start_time)
        (report_reason,event_type,event_id) = struct.unpack_from(
            EVT_EVENT_REPORT_HEADER_PACK_STR, buf,offset)
        cls_ = cls._REPORT_EVENT_TYPES.get(event_type)
        if cls_ is not None:
            res = cls_.parser(datapath,buf,offset + EVT_EVENT_REPORT_HEADER_SIZE
                ,report_reason,event_type,event_id)
            #LOG.info("Finish parsing event report at %.6f, cost time %.6f" %(time.time(), time.time() - start_time ))
            return res
        else:
            return cls(datapath,report_reason,event_type,event_id)

    def __str__(self):
        return "Event report from switch %016x, event ID = %d\n" %(self.datapath.id,self.event_id)

@OFP13EpccEventReport.register_report_event_type(EVT_PORT_STATS_TIMER_TRIGGER)
class OFP13EventReportPortTimer(OFP13EpccEventReport):
    def __init__(self,datapath,report_reason,event_id,
        port_no,interval_sec,interval_msec,
        new_tx_packets,new_tx_bytes,new_rx_packets,new_rx_bytes,
        total_tx_packets,total_tx_bytes,total_rx_packets,total_rx_bytes
        ):
        super(OFP13EventReportPortTimer,self).__init__(datapath,
            report_reason,EVT_PORT_STATS_TIMER_TRIGGER,event_id)
        self.port_no = port_no
        self.interval_sec = interval_sec
        self.interval_msec = interval_msec
        self.new_tx_packets = new_tx_packets
        self.new_tx_bytes = new_tx_bytes
        self.new_rx_packets = new_rx_packets
        self.new_rx_bytes = new_rx_bytes
        self.total_tx_packets = total_tx_packets
        self.total_tx_bytes = total_tx_bytes
        self.total_rx_packets = total_rx_packets
        self.total_rx_bytes = total_rx_bytes

    @classmethod
    def parser(cls,datapath,buf,offset,
        report_reason,event_type,event_id):
        assert event_type == EVT_PORT_STATS_TIMER_TRIGGER
        (
            port_no,interval_sec,interval_msec,
            new_tx_packets,new_tx_bytes,new_rx_packets,new_rx_bytes,
            total_tx_packets,total_tx_bytes,total_rx_packets,total_rx_bytes
        ) = struct.unpack_from(EVT_PORT_TIMER_REPORT_PACK_STR,buf,offset)
        return cls(datapath,report_reason,event_id,
            port_no,interval_sec,interval_msec,
            new_tx_packets,new_tx_bytes,new_rx_packets,new_rx_bytes,
            total_tx_packets,total_tx_bytes,total_rx_packets,total_rx_bytes
            )

    def __str__(self):
        outstr = super(OFP13EventReportPortTimer).__str__()
        outstr += "port stats event report on switch %016x port %d\n" %(self.datapath.id,self.port_no)
        outstr += "In %d seconds %d milliseconds\n" %(self.interval_sec,self.interval_msec)
        outstr += "New: TX = %d packets, %d bytes, RX = %d packets %d bytes\n" %(
            self.new_tx_packets,self.new_tx_bytes,self.new_rx_packets,self.new_rx_bytes)
        outstr += "Total: TX = %d packets, %d bytes, RX = %d packets, %d bytes\n" %(
            self.total_tx_packets,self.total_tx_bytes,self.total_rx_packets,self.total_rx_bytes)
        return outstr

class SingleFlowReport(object):
    def __init__(self,table_id,flow_cookie,duration_sec,duration_nsec,
        new_match_packets,new_match_bytes,total_match_packets,total_match_bytes,
        match,instructions):
        self.length = None
        self.table_id = table_id
        self.flow_cookie = flow_cookie
        self.duration_sec = duration_sec
        self.duration_nsec = duration_nsec
        self.new_match_packets = new_match_packets
        self.new_match_bytes = new_match_bytes
        self.total_match_packets = total_match_packets
        self.total_match_bytes = total_match_bytes
        self.match = match
        self.instructions = instructions

    @classmethod
    def parser(cls,buf,offset):
        _offset = offset
        #LOG.info("Offset = %d" %offset)
        (length,table_id,flow_cookie,duration_sec,duration_nsec,
         new_match_packets,new_match_bytes,total_match_packets,total_match_bytes
            ) = struct.unpack_from("!HB5xQIIQQQQ",buf,offset)
        offset += 56
        #LOG.info("single flow, length = %d" %length)
        match = ofproto_parser.OFPMatch.parser(buf,offset)
        LOG.info(match)
        offset += utils.round_up(match.length, 8)
        
        instructions = []
        inst_length = length - ( offset - _offset )
        #LOG.info("Length of instructions = %d" %inst_length)
        while inst_length > 0:
            inst = ofproto_parser.OFPInstruction.parser(buf,offset)
            offset += inst.len
            inst_length -= inst.len
            instructions.append(inst)
        #LOG.info(instructions)
        single_flow = cls(table_id,flow_cookie,duration_sec,duration_nsec,
            new_match_packets,new_match_bytes,total_match_packets,total_match_bytes,
            match,instructions)
        single_flow.length = length
        return single_flow

    def __str__(self):
        outstr = ""
        outstr += "Single flow, table ID = %d, cookie = %016x\n" %(self.table_id,self.flow_cookie)
        outstr += "Match = %s\n" %self.match
        outstr += "Duration = %d seconds + %d nanoseconds\n" %(self.duration_sec,self.duration_nsec)
        outstr += "New: matched %d packets, %d bytes\n" %(self.new_match_packets,self.new_match_bytes)
        outstr += "Total: matched %d packets, %d bytes\n" %(self.total_match_packets,self.total_match_bytes)
        outstr += "Instructions: %s\n" %self.instructions
        return outstr

OFP13_FLOW_TIMER_REPORT_HEADER_PACK_STR = "!B3xIIII4x"
@OFP13EpccEventReport.register_report_event_type(EVT_FLOW_STATS_TIMER_TRIGGER)
class OFP13EventReportFlowTimer(OFP13EpccEventReport):
    def __init__(self,datapath,report_reason,event_id,
        table_id,out_port,out_group,
        interval_sec, interval_msec,match,single_flows
        ):
        super(OFP13EventReportFlowTimer,self).__init__(datapath,report_reason,
            EVT_FLOW_STATS_TIMER_TRIGGER,event_id)
        self.table_id = table_id
        self.out_port = out_port
        self.out_group = out_group
        self.interval_sec = interval_sec
        self.interval_msec = interval_msec
        self.match = match
        self.single_flows = single_flows

    @classmethod
    def parser(cls,datapath,buf,offset,report_reason,event_type,event_id):
        assert event_type == EVT_FLOW_STATS_TIMER_TRIGGER
        length = len(buf)
        #LOG.info("Event %d Message length = %d" %(event_id,length) )
        #LOG.info("Offset = %d" %offset)
        _offset = offset
        (table_id,out_port,out_group,interval_sec,interval_msec
            ) = struct.unpack_from(OFP13_FLOW_TIMER_REPORT_HEADER_PACK_STR,buf,offset)
        offset += 24
        match = ofproto_parser.OFPMatch.parser(buf,offset)
        offset += utils.round_up(match.length, 8)
        single_flows = []

        while offset < length:
            #LOG.info("One flow")
            try:
                single_flow = SingleFlowReport.parser(buf,offset)
                single_flows.append(single_flow)
                offset += single_flow.length
            except Exception,e:
                #LOG.info("Error in parsing single flows: %s" %e)
                #LOG.info( utils.hex_array(buf[offset:]) )
                break

        return cls(datapath,report_reason,event_id,
            table_id,out_port,out_group,interval_sec,interval_msec,
            match,single_flows)

    def __str__(self):
       outstr = super(OFP13EventReportFlowTimer,self).__str__()
       outstr += "table ID = %d, output port = %d, output group = %d\n" %(self.table_id,self.out_port,self.out_group)
       outstr += "Interval = %d seconds + %d milliseconds\n" %(self.interval_sec,self.interval_msec)
       outstr += "match = %s" %(self.match)
       for single_flow in self.single_flows:
            outstr += str(single_flow)

       return outstr

class EventSwitchEventReply(event.EventBase):
    def __init__(self,reply):

        self.reply = reply

class EventSwitchEventReport(event.EventBase):
    def __init__(self,msg):
        
        self.msg = msg

class OFP13EpccEventMessageHandler(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto.OFP_VERSION]

    _EVENTS = [
        EventSwitchEventReply,
        EventSwitchEventReport,
        ]

    def __init__(self):
        self.name = "EpccEventMessage"
        super(OFP13EpccEventMessageHandler,self).__init__()

    @set_ev_cls(ofp_event.EventOFPExperimenter,MAIN_DISPATCHER)
    def experimenter_message_handler(self,ev):
        msg = ev.msg
        datapath = msg.datapath
        experimenter = msg.experimenter
        exp_type = msg.exp_type

        if experimenter == EPCC_EXPERIMENTER_ID:
            if exp_type == EVT_SUBTYPE_EVENT_REPLY:
                
                reply = OFP13EpccEventReply.parser(datapath,msg.data,0)
                self.send_event_to_observers(EventSwitchEventReply(reply))
            elif exp_type == EVT_SUBTYPE_EVENT_REPORT:
                #LOG.info("Messgage Transaction ID = %d, Total length = %d" %(msg.xid,len(msg.data) ) )
                report = OFP13EpccEventReport.parser(datapath,msg.data,0)
                self.send_event_to_observers( EventSwitchEventReport(report) )
            else:
                LOG.error("unknown subtype %d" %exp_type)
            

    @set_ev_cls(ofp_event.EventOFPErrorMsg,MAIN_DISPATCHER)
    def ofp_error_handler(self,ev):
        msg = ev.msg
        datapath = msg.datapath
        err_type = msg.type
        LOG.info("Error type %s from switch %016x" %(err_type,datapath.id) )