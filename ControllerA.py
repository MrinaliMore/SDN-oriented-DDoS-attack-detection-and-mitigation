'''
This is controller 1 script.
Author: Pranati Kulkarni & Mrinali More
Date: 05/06/2018
CMPE210 course project under Dr.Young Park
'''
import subprocess
from operator import attrgetter
import simple_switch_13
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub

'''
-----------------------------------------------------------------------------------
Main Controller script. 
This script extends the already existing ryu script simple_switch_13.py. 
-----------------------------------------------------------------------------------
'''
class SimpleMonitor(simple_switch_13.SimpleSwitch13):
    # Set an interval for polling switch statistics to 2
    POLLING_INTERVAL = 2
    # Set the bandwidth threshold in Kbits/sec for an attack on a particular port
    ATTACK_THRESHOLD = 4000
    # Set the bandwidth threshold in Kbits/sec for an attacker launching DDoS attack
    ATTACKER_THRESHOLD = 1000
    # To specify if the polled switch statistics should be disclosed or not
    STATS_REPORT = True

    def __init__(self, *args, **kwargs):
        super(SimpleMonitor, self).__init__(*args, **kwargs)
	# Datapath flows known by statistics polling
        self.datapaths = {}
	# Creates thread for polling flow and port statistics
        self.monitor_thread = hub.spawn(self._monitor)
	# Set of attackers
        self.attackers = set()

        # Mapping from switch/port/destination MAC combinations to flow rates
        self.flow_rates = {"sA": [{}, {}, {}],
                           "s1": [{}, {}, {}],
                           "s2": [{}, {}, {}],
                           "sB": [{}, {}, {}],
                           "s3": [{}, {}, {}],
                           "s4": [{}, {}, {}]}

        # Mapping from switches and ports to attached switchtes/hosts
        self.portMaps = {"sA": ["s1", "s2", "sB"],
                         "s1": ["A1h1", "A2h2", "sA"],
                         "s2": ["B1h1", "B2h2", "sA"],
                         "s3": ["C1h1", "C2h2", "sB"],
                         "s4": ["D1h1", "D2h2", "sB"],
                         "sB": ["s3", "s4", "sA"]}

        # Mapping from datapath ids and switch names
        self.dpids = {0x10: "sA",
                      0x1: "s1",
                      0x2: "s2",
                      0x11: "sB",
                      0x3: "s3",
                      0x4: "s4"}

        # Last obtained byte counts for each FLOW to calculate difference for bandwidth usage calculation
        self.flow_byte_counts = {}
        # Last obtained byte counts for each PORT to calculate difference for bandwidth usage calculation
        self.port_byte_counts = {}
        # Set of host on which attack was orginated by other domain
        self.otherdomain = set()

##############################################################################
#                              Main Code                                     #
##############################################################################

    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if not datapath.id in self.datapaths:
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                del self.datapaths[datapath.id]

    def _monitor(self):
        while True:
            for dp in self.datapaths.values():
                self._request_stats(dp)
            hub.sleep(SimpleMonitor.POLLING_INTERVAL)

    def _request_stats(self, datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)
        req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        datapath.send_msg(req)

    # Main entry point for our DDoS detection code.
    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        domainHosts = ['0a:01:00:00:00:01', '0a:02:00:00:00:02', '0b:01:00:00:00:01', '0b:02:00:00:00:02']
        # The (suspected) set of victims identified by the statistics
        victims = set()
        body = ev.msg.body
        # Get id of datapath for which statistics are reported as int
        dpid = int(ev.msg.datapath.id)
        switch = self.dpids[dpid]

        if SimpleMonitor.STATS_REPORT:
            print "-------------- Flow stats for switch ", switch, "-------------------"
        # Iterate through all statistics reported for the flow
        for stat in sorted([flow for flow in body if flow.priority == 1],
                           key=lambda flow: (flow.match['in_port'],
                                             flow.match['eth_dst'])):
	    #print("Stats", stat)
            # Get in and out port + MAC dest of flow
            in_port = stat.match['in_port']
            out_port = stat.instructions[0].actions[0].port
            eth_dst = stat.match['eth_dst']

            # Check if we have a previous byte count reading for this flow and calculate bandwith usage over the last polling interval
            key = (dpid, in_port, eth_dst, out_port)
            rate = 0

            if key in self.flow_byte_counts:
		#print("Key",key)
                cnt = self.flow_byte_counts[key]
                rate = self.bitrate(stat.byte_count - cnt)
		#print("Count: ",cnt, "Rate: ", rate)
            self.flow_byte_counts[key] = stat.byte_count

            if SimpleMonitor.STATS_REPORT:
                print "In Port %8x Eth Dst %17s Out Port %8x Bitrate %f" % (in_port, eth_dst, out_port, rate)

            # Save the bandwith calculated for this flow
            self.flow_rates[switch][in_port - 1][str(eth_dst)] = rate

            # If we find the bandwith for this flow to be higher than the threshold limit, we mark it as potential vicitim
            if rate > SimpleMonitor.ATTACK_THRESHOLD:
		print("*********************************More than threshold*******************************")
		print("Rate: ",rate)
                victim = str(eth_dst)
                if victim in domainHosts:
                    victims.add(victim)

        victims = victims.intersection({'0a:01:00:00:00:01', '0a:02:00:00:00:02'})

        # Identify if the attacker is in inter-domain
        otherdomain = self.dealWithAttackers(victims)
	
	if (otherdomain):
            self.applyIngress()

        if SimpleMonitor.STATS_REPORT:
            print "--------------------------------------------------------------------------------------"

    #Function to identify if the attacker is in intra-domain or inter-domain
    def dealWithAttackers(self, victims):
        # Set of victims attacked by the other domain
        otherdomain = set()
        # Set of attackers in the local domain
        attackers = set()
        for victim in victims:
	    print("--------------Calling getVictim function------------")
            victimHost, victimSwitch, victimPort = self.getVictim(victim)
            print("Identified victim: MAC %s Host %s Switch %s Port %s" % (victim, victimHost, victimSwitch, victimPort))
	    print("--------Calling getAttacker function-----------")
            victimAttackers = self.getAttackers(victim)
            print("Attackers for victim %s: %s" % (victimAttackers, victimHost))

            if not victimAttackers:
                # No attackers identified, thus assume it's originating in the other domain
                otherdomain.add(victim)
            else:
                attackers = attackers.union(victimAttackers)

	    for attacker in attackers:
	        print("Deleting attackers port")
	        self.delFlows(attacker)

        return otherdomain


    # Returns the victim's switch, and port it is connected to
    def getVictim(self, victim):
	print("--------Victim-------",victim)
        victimHost = victim[1].upper() + victim[4].upper() + "h" + victim[16]
        for switch in self.portMaps:
            for port in range(len(self.portMaps[switch])):
                if self.portMaps[switch][port] == victimHost:
		    print("Switch and Port: ",switch,port)
		    print("Port Maps: ",self.portMaps)
                    return victimHost, switch, str(port + 1)

    # Returns the local attackers of a given victim
    def getAttackers(self, victim):
        attackers = set()
        for switch in self.flow_rates:
            for port in range(len(self.flow_rates[switch])):
		print("Switch and Port: ",switch,port)
		#print("Rates: ",self.flow_rates)
                if victim not in self.flow_rates[switch][port]:
                    continue
                if self.flow_rates[switch][port][victim] > SimpleMonitor.ATTACKER_THRESHOLD:
                    attacker = self.portMaps[switch][port]
		    print("Attacker: ",attacker)
                    attackers.add(attacker)		            
        return attackers

    # Delete attacker's port to stop the flow
    def delFlows(self, attacker):
        attackerSwitch, attackerPort = self.getSwitch(attacker)
	subprocess.call(["sudo","ovs-vsctl","del-port",attackerSwitch + "-eth" + attackerPort])
	print("***********************************************")
	print("Port "+attackerPort +" of " +attackerSwitch + " deleted")


    # Apply ingress policy for inter domain attacks.
    def applyIngress(self):
        print("Inter domain attack detected. Applying Ingress Policing")
        subprocess.call(["sudo", "ovs-vsctl", "set", "interface", "s1-eth1", "ingress_policing_burst=100"])
        subprocess.call(["sudo", "ovs-vsctl", "set", "interface", "s1-eth1", "ingress_policing_rate=40"])


    def getSwitch(self, node):
        for switch in self.portMaps:
            if node in self.portMaps[switch]:
                return switch, str(self.portMaps[switch].index(node) + 1)

    # Convert from byte count to bitrate
    @staticmethod
    def bitrate(bytes):
        return bytes * 8.0 / (SimpleMonitor.POLLING_INTERVAL * 1000)

    # Handle receipt of port traffic statistics
    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):
        body = ev.msg.body

        for stat in sorted(body, key=attrgetter('port_no')):
            key = (ev.msg.datapath.id, stat.port_no)
            rx_bitrate, tx_bitrate = 0, 0
            if key in self.port_byte_counts:
                cnt1, cnt2 = self.port_byte_counts[key]
                rx_bitrate = self.bitrate(stat.rx_bytes - cnt1)
                tx_bitrate = self.bitrate(stat.tx_bytes - cnt2)
            self.port_byte_counts[key] = (stat.rx_bytes, stat.tx_bytes)
