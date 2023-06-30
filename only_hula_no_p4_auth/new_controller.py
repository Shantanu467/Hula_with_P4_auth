#!/usr/bin/env python3
import argparse, re, grpc, os, sys, json, subprocess
import networkx as nx
import statistics####

sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'utils/'))
import p4runtime_lib.helper

from p4runtime_lib.switch import ShutdownAllSwitchConnections
from p4runtime_lib.convert import decodeMac, decodeIPv4
from switch_utils import printGrpcError,load_topology,run_ssc_cmd

# for time calculations
from timer import TimeTracker as TimeTracker####
timer = TimeTracker()####
rtt_times = []####

import struct

# Turn on dry run mode
debug = False

#function to calculate crc 32
import binascii
def hex1(n,l):
    # print(n,l)
    x = '%x' % (n,)
    return ('0'*( l-len(x) )) + x

def cksum(values):
    res = 0;
    for a,b in values:
        # print("val- ",a,b)
        # print("hex- ",hex1(a,b))
        val = binascii.crc32( binascii.a2b_hex(hex1(a,b)),res)
        res = val
        # print("val- ",val)
    return res

#### This function is not used in this code and Can be removeds
# # Generate a simple UID for dst_id of each host
# def host_to_dst_id(hosts):
#     return dict(list(zip(hosts, list(range(1, len(hosts) + 1)))))

def mcast_grp_command(mcast_id, port_ids, handle_id):
    port_seq = " ".join(str(e) for e in port_ids)
    create = "mc_mgrp_create " + str(mcast_id)
    node = "mc_node_create 0 " + port_seq
    assoc = "mc_node_associate " + str(mcast_id) + " " + str(handle_id)
    return create + "\n" + node + "\n" + assoc

def install_smart_mcast(mn_topo, switches, p4info_helper):
    # Note(rachit): Hosts are always considered downstream.
    def is_upstream(x, y):
        return x[0] == y[0] and int(x[1]) < int(y[1])

    G = nx.Graph()
    G.add_edges_from(mn_topo.links())
    # Generate mcast commands and store them in config/<switch>
    for switch in mn_topo.switches():
        command = ""
        adjacents = [__a[1] for __a in G.edges(switch)]
        for adj in adjacents:
            mcast_adjs = None
            # If the packet came from an upstream link, cast it to only downstream links
            if is_upstream(switch, adj):
                mcast_adjs = [a for a in adjacents if not is_upstream(switch, a)]
            # If the packet came from a downstream link, cast it at all other links.
            else:
                mcast_adjs = [a for a in adjacents if a != adj]

            mcast_ports = [mn_topo.port(switch, a)[0] for a in mcast_adjs]
            ingress_port = mn_topo.port(switch, adj)[0]
            cmd = mcast_grp_command(ingress_port, mcast_ports,
                                    switches[switch].getAndUpdateHandleId())
            command += (cmd + "\n")
        # Execute mcast setup
        print(run_ssc_cmd(switch, command))

def install_hula_logic(mn_topo, switches, p4info_helper):
    print('In hula logic\n')####
    for sw in mn_topo.switches():
        print(f'Switch s : ',sw)####
        if sw == 's6':####
            continue####
        add_hula_handle_probe = p4info_helper.buildTableEntry(
            table_name="MyIngress.hula_logic",
            match_fields = {
                "hdr.ipv4.protocol": 0x42
            },
            action_name = "MyIngress.hula_handle_probe",
            action_params = {
        })
        add_hula_handle_data_packet = p4info_helper.buildTableEntry(
            table_name="MyIngress.hula_logic",
            match_fields = {
                "hdr.ipv4.protocol": 0x06
            },
            action_name = "MyIngress.hula_handle_data_packet",
            action_params = {
        })
        switches[sw].WriteTableEntry(add_hula_handle_probe, debug)

        hula_dgst = cksum([(0,8),(0,6),(0,2)]) # digest with key(0) and hula paramas
        pkt = struct.pack(
            '!hihih??hhh?chiih??i',  # hi => ether addr, 'hihih' => ether addr
            0,0, #src ether
            0,0, #dst ether
            0x800,
            0,0, # c,c
            0,0,0, # hhh
            0,'B'.encode('ascii'), # ??
            0, #h
            0, #src IP addr
            0, # dst IP addr
            0,0,0,hula_dgst # hula hdr
        )
        # calculate the digest of the packet
        lst = [(2,2),(0,2),(0,4),(0,8),(0,4),(0,8),(2048,4),(0,2),(0,2),(0,4),(0,4),(0,4),(0,2),(66,2),(0,4),(0,8),(0,8),(0,4),(0,2),(0,2),(hula_dgst,8)]
        pkt_dgst = cksum(lst)
        print("dig- ", pkt_dgst)
        # build and send the packet out message
        packet_out = p4info_helper.buildPacketOut(
            payload = pkt,
            metadata = {
                1: b'\x00\x02',
                2: b'\x00\x00',
                3: (pkt_dgst).to_bytes(4, byteorder = 'big')
            }
        )
        # switches[sw].PacketOut(packet_out) #Why?


        switches[sw].WriteTableEntry(add_hula_handle_data_packet, debug)

def install_tables(mn_topo, switches, p4info_helper):
    # Install entries for hula_logic
    install_hula_logic(mn_topo, switches, p4info_helper)
    # Install rule to map each host to dst_tor
    for (x, y) in mn_topo.links():
        switch = None
        host= None
        if x.startswith("h") and y.startswith("s"):
            switch = y
            host = x
        elif y.startswith("h") and x.startswith("s"):
            switch = x
            host = y
        else:
            continue
        host_ip = mn_topo.nodeInfo(host)['ip'].split('/')[0]
        dst_tor_num = int(switch[1:])
        port = mn_topo.port(switch, host)[0]

        # Install entries for edge forwarding.
        add_edge_forward = p4info_helper.buildTableEntry(
            table_name="MyIngress.edge_forward",
            match_fields = {
                "hdr.ipv4.dstAddr": host_ip
            },
            action_name="MyIngress.simple_forward",
            action_params={
                "port": port,
            })
        switches[switch].WriteTableEntry(add_edge_forward, debug)

        for sw in mn_topo.switches():
            self_id = int(sw[1:])
            print('self_id : ', self_id)####
            if self_id == 6:####Why?
                continue####
            # Install entries to calculate get_dst_tor
            add_host_dst_tor = p4info_helper.buildTableEntry(
                table_name="MyIngress.get_dst_tor",
                match_fields = {
                    "hdr.ipv4.dstAddr": host_ip
                },
                action_name="MyIngress.set_dst_tor",
                action_params={
                    "dst_tor": dst_tor_num,
                    "self_id": self_id
                })
            print("sw- ",sw)
            print("dst_tor- ",host_ip, dst_tor_num, self_id)

            timer.record_start_timestamp()####
            switches[sw].WriteTableEntry(add_host_dst_tor, debug)
            timer.record_end_timestamp()####
            rtt_times.append(timer.time_elapsed)####
            print(f'Switch : {sw} :: time : {timer.time_elapsed}')####

#### This function is not used in this code and Can be removed
# [port no, switch]
# def insert_keys(mn_topo, switches, p4info_helper, port_map, keys):
#     for sw in mn_topo.switches():
#         print("sw- ", sw)
#         if sw == 's6':####
#             continue####
#         for link in port_map[sw]:
#             if (link[1] == '6' or link[0] == '6'):#### #or (link[1] == '5' and link[0] == '1') or (link[1] == '0' and link[0] == '4'):
#                 continue####
#             print("link- ",link[0], link[1])
#             register_id = p4info_helper.get_registers_id("MyIngress.keys")
#             port = link[0]
#             skey = keys[int(link[1])]
#             print(f'Port : {port} Skey : {skey}')
#             packet = struct.pack('!iii', register_id, port, skey)
#             pkt_dgst = cksum([(1,2),(1,2),(register_id,8),(port,8),(skey,8)])
#             packet_out = p4info_helper.buildPacketOut(
#                 payload = packet,
#                 metadata = {
#                     1: b'\x00\x01',
#                     2: b'\x00\x01',
#                     3: pkt_dgst.to_bytes(4,byteorder='big'),
#                 }
#             )
#             switches[sw].PacketOut(packet_out)



def main(p4info_file_path, bmv2_file_path, topo_file_path):
    # Instantiate a P4Runtime helper from the p4info file
    p4info_helper = p4runtime_lib.helper.P4InfoHelper(p4info_file_path)

    try:
        # Load the topology from the JSON file
        switches, mn_topo = load_topology(topo_file_path)

        # Establish a P4 Runtime connection to each switch
        for bmv2_switch in list(switches.values()):
            bmv2_switch.MasterArbitrationUpdate()
            print("Established as controller for %s" % bmv2_switch.name)

        # Load the P4 program onto each switch
        for bmv2_switch in switches.values():
            print(bmv2_switch.name)####
            if bmv2_switch.name == 's6':####
                continue####
            bmv2_switch.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
                                                    bmv2_json_file_path=bmv2_file_path)
            print ("Installed P4 Program using SetForwardingPipelineConfig on %s" % bmv2_switch.name)

        install_smart_mcast(mn_topo, switches, p4info_helper)
        install_tables(mn_topo, switches, p4info_helper)

    except KeyboardInterrupt:
        print(" Shutting down.")
    except grpc.RpcError as e:
        printGrpcError(e)

    ShutdownAllSwitchConnections()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='P4Runtime Controller')
    parser.add_argument('--p4info', help='p4info proto in text format from p4c',
                        type=str, action="store", required=False,
                        default='./build/switch1.p4info')
    parser.add_argument('--bmv2-json', help='BMv2 JSON file from p4c',
                        type=str, action="store", required=False,
                        default='./build/switch1.json')
    parser.add_argument('--topo', help='Topology file',
                        type=str, action="store", required=False,
                        default='topology.json')
    args = parser.parse_args()

    if not os.path.exists(args.p4info):
        parser.print_help()
        print("\np4info file not found: %s\nHave you run 'make'?" % args.p4info)
        parser.exit(1)
    if not os.path.exists(args.bmv2_json):
        parser.print_help()
        print("\nBMv2 JSON file not found: %s\nHave you run 'make'?" % args.bmv2_json)
        parser.exit(1)
    if not os.path.exists(args.topo):
        parser.print_help()
        print("\nTopology file not found: %s" % args.topo)
        parser.exit(1)
    main(args.p4info, args.bmv2_json, args.topo)

    print(f'\nRTT times : {rtt_times}')####
    print(f'Average RTT time : {statistics.fmean(rtt_times)}')####
