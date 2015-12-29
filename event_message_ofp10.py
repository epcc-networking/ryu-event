import os
import time
import logging

import struct

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls

import ryu.ofproto.ofproto_v1_0 as ofproto
import ryu.ofproto.ofproto_v1_0_parser as ofproto_parser

from ryu import utils
from ryu.lib.pack_utils import msg_pack_into
from event_message_common import *

UINT64_MAX = 0xffFFffFFffFFffFF

LOG = logging.getLogger("ryu.epcc.event_msg_ofp10")

@ofproto_parser.OFPVendor.register_vendor(EPCC_EXPERIMENTER_ID)
class OFP10EpccEventHeader(ofproto_parser.OFPVendor):
    _EVT_SUBTYPES = {}

    @staticmethod
    def register_evt_subtype(subtype):
        def _register_evt_subtype(cls):
            cls.cls_subtype = subtype
            OFP10EpccEventHeader._EVT_SUBTYPES[cls.cls_subtype] = cls
            return cls
        return _register_evt_subtype

    def __init__(self,datapath,subtype):
        super(OFP10EpccEventHeader,self).__init__(datapath)
        self.vendor = EPCC_EXPERIMENTER_ID
        self.subtype = subtype

    def serialize_header(self):
        super(OFP10EpccEventHeader,self).serialize_header()
        msg_pack_into(EVT_SUBTYPE_STRING,self.buf,ofproto.OFP_HEADER_SIZE,
            self.vendor,self.subtype)

    @classmethod
    def parser(cls,datapath, buf, offset):
        LOG.info("event message header parser")
        vendor,subtype = struct.unpack_from(EVT_SUBTYPE_STRING,
            buf,offset + ofproto.OFP_HEADER_SIZE)
        cls_ = cls._EVT_SUBTYPES.get(subtype)
        return cls_.parser(datapath,buf,offset + ofproto.OFP_HEADER_SIZE + EVT_HEADER_SIZE)

    
@OFP10EpccEventHeader.register_evt_subtype(EVT_SUBTYPE_EVENT_REQUEST)
class OFP10EpccEventRequest(OFP10EpccEventHeader):
    _REQUEST_EVENT_TYPES = {}
    @staticmethod
    def register_request_event_type(event_type):
        def _register_request_event_type(cls):
            cls.cls_event_type = event_type
            OFP10EpccEventRequest._REQUEST_EVENT_TYPES[event_type] = cls
            return cls
        return _register_request_event_type

    def __init__(self,datapath,
        request_type,event_periodic,event_type,event_id = 0):
        super(OFP10EpccEventRequest,self).__init__(datapath,EVT_SUBTYPE_EVENT_REQUEST)
        self.request_type = request_type
        self.event_id = event_id
        self.event_periodic = event_periodic
        self.event_type = event_type

    def serialize_req_header(self):
        self.serialize_header()
        msg_pack_into(EVT_REQUEST_HEADER_FORMAT_STR
            ,self.buf, ofproto.OFP_HEADER_SIZE + EVT_HEADER_SIZE,
            self.request_type,self.event_periodic,self.event_type,self.event_id)



@OFP10EpccEventRequest.register_request_event_type(EVT_PORT_STATS_TIMER_TRIGGER)
class OFP10EventRequestPortTimer(OFP10EpccEventRequest):
    def __init__(self,datapath,request_type, event_periodic,event_id = 0,
        port_no = 0,interval_sec = 0, interval_msec = 0, event_conditions = 0,
        threshold_tx_packets = UINT64_MAX, threshold_tx_bytes = UINT64_MAX,
        threshold_rx_packets = UINT64_MAX, threshold_rx_bytes = UINT64_MAX
        ):
        super(OFP10EventRequestPortTimer,self).__init__(datapath,
            request_type,event_periodic,EVT_PORT_STATS_TIMER_TRIGGER,event_id)
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
        offset = ofproto.OFP_HEADER_SIZE + EVT_HEADER_SIZE + EVT_REQUEST_HEADER_SIZE
        msg_pack_into(EVT_PORT_TIMER_REQUEST_PACK_STR, self.buf, offset,
            self.port_no,self.event_conditions,
            self.interval_sec,self.interval_msec,
            self.threshold_tx_packets,self.threshold_tx_bytes,
            self.threshold_rx_packets,self.threshold_rx_bytes)


@OFP10EpccEventRequest.register_request_event_type(EVT_FLOW_STATS_TIMER_TRIGGER)
class OFP10EventRequestFlowTimer(OFP10EpccEventRequest):
    def __init__(self,datapath,request_type,event_periodic,event_id = 0,
        table_id = 0xff, out_port = ofproto.OFPP_NONE, match = None, 
        flow_cookie = 0, cookie_mask = 0,
        interval_sec = 0, interval_msec = 0, event_conditions = 0,
        threshold_new_match_packets = UINT64_MAX, threshold_new_match_bytes = UINT64_MAX,
        threshold_total_match_packets = UINT64_MAX, threshold_total_match_bytes = UINT64_MAX
        ):
        super(OFP10EventRequestFlowTimer,self).__init__(datapath,
            request_type, event_periodic, EVT_FLOW_STATS_TIMER_TRIGGER, event_id)
        self.table_id = table_id
        self.out_port = out_port
        if match is None:
            match = ofproto_parser.OFPMatch()
        self.match = match
        self.flow_cookie = flow_cookie
        self.cookie_mask = cookie_mask
        self.interval_sec = interval_sec
        self.interval_msec = interval_msec
        self.event_conditions = event_conditions
        self.threshold_new_match_packets = threshold_new_match_packets
        self.threshold_new_match_bytes = threshold_new_match_bytes
        self.threshold_total_match_packets = threshold_total_match_packets
        self.threshold_total_match_bytes = threshold_total_match_bytes

    def _serialize_body(self):
        self.serialize_req_header()
        offset = ofproto.OFP_HEADER_SIZE + EVT_HEADER_SIZE + EVT_REQUEST_HEADER_SIZE
        self.match.serialize(self.buf,offset)
        offset += ofproto.OFP_MATCH_SIZE
        msg_pack_into("!BxHQQ",self.buf,offset,
            self.table_id,self.out_port,self.flow_cookie,self.cookie_mask)
        offset += 20
        msg_pack_into("!H2xII",self.buf,offset,self.event_conditions,self.interval_sec,self.interval_msec)
        offset += 12
        msg_pack_into("!QQQQ",self.buf,offset,self.threshold_new_match_packets,self.threshold_new_match_bytes,
            self.threshold_total_match_packets,self.threshold_total_match_bytes)
        offset += 32


@OFP10EpccEventHeader.register_evt_subtype(EVT_SUBTYPE_EVENT_REPLY)
class OFP10EpccEventReply(OFP10EpccEventHeader):
    def __init__(self,datapath,event_status,event_type,event_id):
        super(OFP10EpccEventReply,self).__init__(datapath,EVT_SUBTYPE_EVENT_REPLY)
        self.event_status = event_status
        self.event_type = event_type
        self.event_id = event_id

    @classmethod
    def parser(cls,datapath,buf,offset):
        (event_status,event_type,event_id) = struct.unpack_from(
            EVT_EVENT_REPLY_PACK_STR,buf,offset
            )
        return cls(datapath,event_status,event_type,event_id)


@OFP10EpccEventHeader.register_evt_subtype(EVT_SUBTYPE_EVENT_REPORT)
class OFP10EpccEventReportHeader(OFP10EpccEventHeader):
    _REPORT_EVENT_TYPES = {}
    def __init__(self,datapath,report_reason,event_type,event_id):
        super(OFP10EpccEventReportHeader,self).__init__(datapath,EVT_SUBTYPE_EVENT_REPORT)
        self.report_reason = report_reason
        self.event_type = event_type
        self.event_id = event_id

    @staticmethod
    def register_report_event_type(event_type):
        def _register_report_event_type(cls):
            cls.cls_event_type = event_type
            OFP10EpccEventReportHeader._REPORT_EVENT_TYPES[event_type] = cls
            return cls
            
        return _register_report_event_type

    @classmethod
    def parser(cls,datapath,buf,offset):
        LOG.info("Event report header parser")
        (report_reason,event_type,event_id) = struct.unpack_from(
            EVT_EVENT_REPORT_HEADER_PACK_STR, buf, offset)
        cls_ = cls._REPORT_EVENT_TYPES.get(event_type)
        if cls_ is not None:
            return cls_.parser(datapath,buf,offset + EVT_EVENT_REPORT_HEADER_SIZE,
                report_reason,event_type,event_id)
        else:
            return cls(datapath,report_reason,event_type,event_id)

@OFP10EpccEventReportHeader.register_report_event_type(EVT_PORT_STATS_TIMER_TRIGGER)
class OFP10EpccPortTimerReport(OFP10EpccEventReportHeader):
    def __init__(self,datapath,report_reason,event_id,
        port_no,interval_sec,interval_msec,
        new_tx_packets, new_tx_bytes, new_rx_packets, new_rx_bytes,
        total_tx_packets, total_tx_bytes, total_rx_packets, total_rx_bytes
        ):
        super(OFP10EpccPortTimerReport,self).__init__(datapath,report_reason
            ,EVT_PORT_STATS_TIMER_TRIGGER,event_id)
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
    def parser(cls,datapath,buf,offset,report_reason,event_type,event_id):
        (port_no,interval_sec,interval_msec,
            new_tx_packets,new_tx_bytes,new_rx_packets,new_rx_bytes,
            total_tx_packets,total_tx_bytes,total_rx_packets,total_rx_bytes
        ) = struct.unpack_from(EVT_PORT_TIMER_REPORT_PACK_STR,buf,offset)

        return cls(datapath, report_reason, event_id,
            port_no, interval_sec, interval_msec,
            new_tx_packets, new_tx_bytes, new_rx_packets, new_rx_bytes,
            total_tx_packets, total_tx_bytes, total_rx_packets,total_rx_bytes)

    def __str__(self):
        outstr = ""
        outstr += "Port Stat event from switch %016x, event ID = %08x \n" %(self.datapath.id,self.event_id)
        outstr += "port %d: in %d seconds + %d milliseconds\n" %(self.port_no,self.interval_sec,self.interval_msec)
        outstr += "New : TX = %d packets %d bytes, RX = %d packets %d bytes\n" %(
            self.new_tx_packets,self.new_tx_bytes,self.new_rx_packets,self.new_tx_bytes)
        outstr += "Total: TX = %d packets %d bytes, RX = %d packets %d bytes\n" %(
            self.total_tx_packets,self.total_tx_bytes,self.total_rx_packets,self.total_rx_bytes)
        return outstr 

class SingleFlowReport(object):
    def __init__(self,table_id,match,flow_cookie,
            duration_sec,duration_nsec,
            new_match_packets, new_match_bytes, total_match_packets,total_match_bytes,
            actions
            ):
        
        self.length = None
        self.table_id = table_id
        self.match = match
        self.flow_cookie = flow_cookie
        self.duration_sec = duration_sec
        self.duration_nsec = duration_nsec
        self.new_match_packets = new_match_packets
        self.new_match_bytes = new_match_bytes
        self.total_match_packets = total_match_packets
        self.total_match_bytes = total_match_bytes
        self.actions = actions

    @classmethod
    def parser(cls,buf,offset):
    
        _offset = offset
        (length,) = struct.unpack_from("!H",buf,offset)
        length = length
        offset += 2
        (table_id,) = struct.unpack_from("!Hx",buf,offset)
        offset += 2
        match = ofproto_parser.OFPMatch.parse(buf,offset)
        offset += ofproto.OFP_MATCH_SIZE
        (flow_cookie,duration_sec,duration_nsec) = struct.unpack_from(
            "!QII", buf, offset
            )
        offset += 16
        (new_match_packets,new_match_bytes,total_match_packets,total_match_bytes) = struct.unpack_from(
            "!QQQQ", buf, offset
            )

        offset += 32
        action_len = length - (offset - _offset)
        actions = []
        while action_len > 0:
            action = ofproto_parser.OFPAction.parser(buf,offset)
            offset += action.len
            action_len -= action.len
            actions.append(action)

        single_flow = cls(table_id,match,flow_cookie,
            duration_sec,duration_nsec,
            new_match_packets,new_match_packets,total_match_packets,total_match_bytes,
            actions)
        single_flow.length = length

        return single_flow

    def __str__(self):
        outstr = ""
        outstr += "Flow match: %s\n" %str(self.match)
        outstr += "Table ID = %d\n" %self.table_id
        outstr += "flow cookie = %016x\n" %self.flow_cookie
        outstr += "Actions: %s\n" %str(self.actions)
        outstr += "Duration: %d seconds + %d nanoseconds\n" %(self.duration_sec,self.duration_nsec)
        outstr += "New: matched %d packets %d bytes\n" %(self.new_match_packets,self.new_match_bytes)
        outstr += "Total: matched %d packets %d bytes\n" %(self.total_match_packets,self.total_match_bytes)
        return outstr


@OFP10EpccEventReportHeader.register_report_event_type(EVT_FLOW_STATS_TIMER_TRIGGER)
class OFP10EpccFlowTimerReport(OFP10EpccEventReportHeader):
    def __init__(self,datapath,report_reason,event_id,
            table_id, out_port, match,interval_sec, interval_msec,
            single_flows):
        super(OFP10EpccFlowTimerReport,self).__init__(datapath,report_reason,EVT_FLOW_STATS_TIMER_TRIGGER,event_id)
        self.table_id = table_id
        self.out_port = out_port
        self.match = match
        self.interval_sec = interval_sec
        self.interval_msec = interval_msec
        self.single_flows = single_flows

    @classmethod 
    def parser(cls,datapath,buf,offset,report_reason,event_type,event_id):
        match = ofproto_parser.OFPMatch.parse(buf,offset)
        length = len(buf)
        offset += ofproto.OFP_MATCH_SIZE
        (table_id,out_port,interval_sec,interval_msec) = struct.unpack_from(
            "!BxHII", buf, offset
            )
        offset += 12
        single_flows = []
        while offset < length:
            single_flow = SingleFlowReport.parser(buf,offset)
            offset += single_flow.length
            single_flows.append(single_flow)

        return cls(datapath,report_reason,event_id,
            table_id, out_port, match,
            interval_sec, interval_msec, single_flows)

    def __str__(self):
        outstr = ""
        outstr += "Flow stats event report from switch %016x, event ID = %08x\n" %(self.datapath.id,self.event_id)
        outstr += "Table ID = %d,output port = %d\n" %(self.table_id,self.out_port)
        outstr += "In %d seconds + %d milliseconds\n" %(self.interval_sec,self.interval_msec)
        outstr += "%d flows:\n" %len(self.single_flows)
        for flow in self.single_flows:
            outstr += str(flow)
        return outstr



class OFP10EpccEventMessageHandler(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto.OFP_VERSION] #OFP10
    def __init__(self):
        self.name = "EpccEventMessage"
        super(OFP10EpccEventMessageHandler,self).__init__()
        LOG.info("Event message handler on")

    @set_ev_cls(ofp_event.EventOFPVendor,MAIN_DISPATCHER)
    def vendor_handler(self,event):
        LOG.info("vendor handler")
        data = event.msg.data
        datapath = event.msg.datapath
        vendor = event.msg.vendor
        subtype = data.subtype


        if vendor == EPCC_EXPERIMENTER_ID:
            LOG.info( type(data) )
            if subtype == EVT_SUBTYPE_EVENT_REPLY:
                LOG.info("Event reply")
            if subtype == EVT_SUBTYPE_EVENT_REPORT:
                LOG.info("Event Report")
                if data.event_type == EVT_PORT_STATS_TIMER_TRIGGER:
                    LOG.info("Port event report")
                    LOG.info(data)
                if data.event_type == EVT_FLOW_STATS_TIMER_TRIGGER:
                    LOG.info("Flow event report")
                    LOG.info(data)
                    report = data
            