/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

// const bit<16> TYPE_IPV4 = 0x800;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

#define CPU_PORT 155

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
typedef bit<9> port_id_t;
typedef bit<8> util_t;
typedef bit<24> tor_id_t;
typedef bit<48> time_t;

/* Constants about the topology and switches. */
const port_id_t NUM_PORTS = 255;
const tor_id_t NUM_TORS = 512;
const bit<32> EGDE_HOSTS = 4;

/* Declaration for the various packet types. */
const bit<16> TYPE_IPV4 = 0x800;
const bit<8> PROTO_HULA = 0x42;
const bit<8> PROTO_TCP = 0x06;


//packet out
@controller_header("packet_out")
header packet_out_header_t{
    bit<8> hdrType;
    bit<8> msgType;  //0-read, 1-write
    bit<32> pktDgst;
}

//packet in
@controller_header("packet_in")
header packet_in_header_t{
    bit<8> hdrType;
    bit<8> msgType;  //0-read, 1-write
    bit<32> pktDgst;
}

header packet_out_reg {
    bit<32> regId;
    bit<32> regIndex;
    bit<32> value;
}

header action_h {
    bit<8> hula_handle_probe_h;
    bit<8> hula_handle_data_packet_h;
}

header hula_t {
    bit<24> dst_tor;
    bit<8> path_util;
    bit<32> digest;
}

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header tcp_t {
  bit<16> srcPort;
  bit<16> dstPort;
  bit<32> seq;
  bit<32> ack;
  bit<4> dataofs;
  bit<3> reserved;
  bit<9> flags;
  bit<32> window;
  bit<16> chksum;
  bit<16> urgptr;
}

struct metadata {
    bit<9> nxt_hop;
    bit<32> self_id;
    bit<32> dst_tor;
    bit<8> validated;
    bit<32> cal_dgst;
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    tcp_t        tcp;
    hula_t       hula;
    packet_out_header_t packet_out;
    packet_in_header_t packet_in;
    action_h act;
    packet_out_reg packet_reg;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        //transition parse_ethernet;
        transition select(standard_metadata.ingress_port){
            CPU_PORT: parse_packet_out;
            default: parse_ethernet;
        }
    }

    state parse_packet_out {
        packet.extract(hdr.packet_out);
        transition select(hdr.packet_out.hdrType){
            0x01: parse_packet_reg;
            0x02: parse_ethernet;
        }
    }

    state parse_packet_reg {
        packet.extract(hdr.packet_reg);
        transition accept;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
          PROTO_HULA: parse_hula;
          PROTO_TCP: parse_tcp;
          default: accept;
        }
    }

    state parse_hula {
        packet.extract(hdr.hula);
        transition accept;
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;
    }

}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    action drop() {
        mark_to_drop(standard_metadata);
    }

##########################################################################################################################################
    ################################################### commented out code below, can be deleted but left for reference
    /*action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
    }

    action hula_forward(egress_spec port){
        standard_metadata.egress_spec = port;
        if(standard_metadata.egress_spec == 1){
            hdr.hula.path_util = 30;
        }
    }

    table hula_fwd {
        key = {
            hdr.ipv4.protocol: exact;
        }
        actions = {
            hula_forward;
            drop;
        }
        size = 4;
        default_action = drop();
    }

    apply {
        if (hdr.ipv4.isValid()) {
            ipv4_lpm.apply();
        }

        if (hdr.hula.isValid()) {
            hula_fwd.apply();
        }
    }*/
    ################################################### commented out code above, can be deleted but left for reference 
####################################################################################################################################################
    action packet_forward(egressSpec_t port){
        if(hdr.hula.isValid()){
            hdr.hula.path_util = 0;
        }
        standard_metadata.egress_spec = port;
    }

    table forward_packet{
        key = {
            standard_metadata.ingress_port: exact;
            //hdr.ipv4.dstAddr: exact;
        }

        actions = {
            packet_forward;
            drop;
        }

        size = 10;
        default_action = drop();
    }

    apply{
        forward_packet.apply();
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
     apply {
        update_checksum(
        hdr.ipv4.isValid(),
            { hdr.ipv4.version,
              hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.packet_in);
        packet.emit(hdr.act);
        packet.emit(hdr.packet_reg);
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
        packet.emit(hdr.hula);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
