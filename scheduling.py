from ryu.base import app_manager
from ryu.controller import event,ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls

from ryu.lib.hub import spawn

from collections import defaultdict
import time

import common

class FlowsScheduler(app_manager.RyuApp):
    def __init__(self,*args,**kwargs):
        super(FlowsScheduler,self).__init__(args,kwargs)
        self.name = "Flow-scheduler"
        self.enable_schedule = False
        self.schedule_interval = 1.0
        self.schedule_thread = None


    @set_ev_cls(common.EventStartScheduling)
    def start_schedule(self,ev):
        self.enable_schedule = True
        self.logger.info("Start scheduling ")
        self.schedule_thread = spawn(self.schedule_loop)

    @set_ev_cls(common.EventPauseScheduling)
    def pause_schedule(self,ev):
        self.enable_schedule = False
        self.logger.info("Pause scheduling")


    def get_fat_tree_path_through_core(self,src_dpid,dst_dpid,core_dpid):
        up_aggr_dpid = None
        down_aggr_dpid = None
        adj = common.adj
        #self.logger.info("find path between %016x and %016x through core %016x" 
        #    %(src_dpid,dst_dpid,core_dpid) )
        for aggr_switch in common.fat_tree['aggrs']:
            aggr_dpid = aggr_switch.datapath.id
            if adj[src_dpid][aggr_dpid] is not None and adj[aggr_dpid][core_dpid] is not None:
                up_aggr_dpid = aggr_dpid
                #self.logger.info("Up: %016x" %up_aggr_dpid)

            if adj[core_dpid][aggr_dpid] is not None and adj[aggr_dpid][dst_dpid] is not None:
                down_aggr_dpid = aggr_dpid
                #self.logger.info("Down: %016x" %down_aggr_dpid)

        if up_aggr_dpid is not None and down_aggr_dpid is not None:
            #self.logger.info("Path : %016x --> %016x through core %016x is %016x->%016x->%016x->%016x->%016x"
            #    %(src_dpid,dst_dpid,core_dpid,src_dpid,up_aggr_dpid,core_dpid,down_aggr_dpid,dst_dpid) )
            return [
                adj[src_dpid][up_aggr_dpid], adj[up_aggr_dpid][core_dpid],
                adj[core_dpid][down_aggr_dpid],adj[down_aggr_dpid][dst_dpid]
            ]
        else:
            #self.logger.info("???")
            return None

    #returns None if no path is found; returns empty list [] if we do not change its path.
    def assign_path(self,flow_record,method = None ):
        src_dpid = None 
        dst_dpid = None
        src_port_no = None
        dst_port_no = None

        match = flow_record.match
        adj = common.adj
        if flow_record.ofp_version >= 0x02:
            if 'ipv4_src' in match:
                (src_dpid,src_port_no) = common.ip_to_port[ match['ipv4_src'] ]
            elif 'eth_src' in match:
                (src_dpid,src_port_no) = common.mac_to_port[ match['eth_src'] ]
            if 'ipv4_dst' in match:
                (dst_dpid,dst_port_no) = common.ip_to_port[ match['ipv4_dst'] ]
            elif 'eth_dst' in match:
                (dst_dpid,dst_port_no) = common.mac_to_port[ match['eth_dst'] ]

        if src_dpid is None or dst_dpid is None:
            return None

        #self.logger.info("find all paths between %016x and %016x" %(src_dpid,dst_dpid))
        if src_dpid == dst_dpid:
            return []


        if common.fat_tree['build_done']:
            full_rate = common.RATE_1Gbps
            paths = []
            same_pod = False
            if flow_record.assigned:
                #self.logger.info("Already assigned a path for flow %s" %(flow_record.match) )
                path_available = True
                if flow_record.same_pod:
                    aggr_dpid = flow_record.assigned_aggr_dpid
                    old_path = [ adj[src_dpid][aggr_dpid], adj[aggr_dpid][dst_dpid] ]
                else:
                    core_dpid = flow_record.assigned_core_dpid
                    old_path = self.get_fat_tree_path_through_core(src_dpid,dst_dpid,core_dpid)

                for link in old_path:
                    if link is None or flow_record.bw_demand > full_rate - link.reserved_bw:
                        path_available = False
                        break

                if path_available:
                    for link in old_path:
                        link.reserved_bw += flow_record.bw_demand
                    #self.logger.info("use old path.")
                    return []

            #self.logger.info("Find new path.")
            for aggr_switch in common.fat_tree['aggrs']:
                aggr_dpid = aggr_switch.datapath.id
                if adj[src_dpid][aggr_dpid] is not None and adj[aggr_dpid][dst_dpid] is not None:
                    #self.logger.info("Same pod, go through aggregation switch %016x" %aggr_dpid)
                    path = [ adj[src_dpid][aggr_dpid], adj[aggr_dpid][dst_dpid] ]
                    same_pod = True
                    flow_record.same_pod = True
                    paths.append(path)

            if not same_pod:
                for core_switch in common.fat_tree['cores']:
                    core_dpid = core_switch.datapath.id
                    path = self.get_fat_tree_path_through_core(src_dpid,dst_dpid,core_dpid)
                    if path is not None and len(path) > 0:
                        paths.append(path)

            if len(paths) < 1:
                return None

            if method == common.PATH_CHOOSE_FIRST_FIT:
                path_found = False
                assigned_path = None
                for path in paths:
                    path_available = True
                    self.logger.info(path)
                    for link in path:
                        if flow_record.bw_demand > full_rate - link.reserved_bw:
                            path_available = False
                            break
                    if path_available:
                        #self.logger.info("First fit: path %s" %path)
                        assigned_path = path
                        path_found = True
                        break

                if not path_found:
                    hash_val = hash( flow_record.flow_ip_pair )
                    idx = hash_val % len(paths)
                    assigned_path = paths[idx]
                    #self.logger.info("No fit path, path %d: %s is chosen." %(idx,assigned_path) )

                if same_pod:
                    flow_record.assigned = True
                    flow_record.same_pod = True
                    flow_record.assigned_aggr_dpid = assigned_path[0].dst_dpid
                else:
                    flow_record.assigned = True
                    flow_record.same_pod = False
                    flow_record.assigned_core_dpid = assigned_path[1].dst_dpid

                return assigned_path



    def schedule_elephant_flows(self):
        active_elephants = []
        active_elephant_num = 0
        flow_src = defaultdict( lambda:0 ) 
        flow_dst = defaultdict( lambda:0 )
        start_time = time.time()
        for hash_val in common.registered_elephants:
            flow_record = common.registered_elephants[hash_val]
            if flow_record is not None and flow_record.update_time > start_time - 2:
                ip_src = flow_record.flow_ip_pair[0]
                ip_dst = flow_record.flow_ip_pair[1]

                active_elephants.append(flow_record)
                flow_src[ip_src] += 1
                flow_dst[ip_dst] += 1

                active_elephant_num += 1

        #self.logger.info("%d/%d active elephant flows" %(active_elephant_num,len(common.registered_elephants) ) )

        for u in common.adj:
            for v in common.adj[u]:
                if common.adj[u][v] is not None:
                    common.adj[u][v].reserved_bw = 0


        for flow_record in active_elephants:
            ip_src = flow_record.flow_ip_pair[0]
            ip_dst = flow_record.flow_ip_pair[1]
            flow_record.bw_demand = 1000 * 1000 * 1000 / max( 1, flow_src[ip_src], flow_dst[ip_dst] )
            #self.logger.info("Flow %s need bandwidth %.0f Mbps" %(flow_record.match, flow_record.bw_demand / ( 1000 * 1000) ) )
            path = self.assign_path(flow_record,method = common.PATH_CHOOSE_FIRST_FIT)
            
            if path is not None and len(path) > 0:
                for link in reversed(path):
                    src_switch = common.switch_list[link.src_dpid]
                    match = flow_record.match
                    out_port = link.src_port_no
                    parser = src_switch.datapath.ofproto_parser
                    actions = [parser.OFPActionOutput(out_port)]
                    src_switch.add_flow(match = match, actions = actions, priority = common.DEFAULT_PRIORITY)
            elif path is None:
                self.logger.debug("Path for flow %s not found?" %(flow_record.match) )
            elif path == []:
                self.logger.debug("Path for flow %s not changed" %(flow_record.match) )
            


    def do_schedule(self):
        start_time = time.time()
        self.logger.info("***Do schedule at %s:%.0f***" %( time.strftime("%Y-%m-%d %H:%M:%S"),(start_time % 1 * 1000) ) )
        self.schedule_elephant_flows()

        self.logger.info("Scheduling cost time %.3f" %( time.time() - start_time))
        

    def schedule_loop(self):
        while self.enable_schedule:
            self.do_schedule()
            time.sleep(self.schedule_interval)