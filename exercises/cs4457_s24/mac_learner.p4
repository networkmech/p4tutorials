/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;
const bit<8> TYPE_ICMP = 0x01;

#define MAX_FLOWS   1024


/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
typedef bit<48> time_t;

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

header icmp_t {
    bit<16> typeCode;
    bit<16> hdrChecksum;
}

struct metadata {
    bit<32> hash1;
    bit<32> hash2;
}

struct values_t {
    bit<1> exist;
    bit<9> interface;
}

struct headers {
    ethernet_t      ethernet;
    ipv4_t          ipv4;
    icmp_t          icmp;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
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
            TYPE_ICMP: parse_icmp;
            default: accept;
        }
    }

    state parse_icmp {
        packet.extract(hdr.icmp);
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
        standard_metadata.egress_spec = 0;
    }

    table firewall_table {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            drop;
            NoAction;
        }
        size = MAX_FLOWS;
        default_action = NoAction;
    }

    // Register, or in-switch hashtable, 
    // for keeping the hash(MAC)--interface mapping.
    register<bit<9>>(MAX_FLOWS) mac_intf_table;

    apply {

        if (hdr.ethernet.isValid()) {

            // The variable that will hold the switch interface number that was retreived 
            // from the mac_intf_table in this switch.
            // 0 means the packet will be dropped. That is the default behavior.
            bit<9> intf_in_table = 0; 

            // variable meta.hash1 holds the hash result when (hdr.ethernet.srcAddr) is hashed by crc32.
            // variable meta.hash2 holds the hash result when (hdr.ethernet.dstAddr) is hashed by crc32.
            hash(meta.hash1, HashAlgorithm.crc32, (bit<16>)0, {hdr.ethernet.srcAddr}, (bit<32>)MAX_FLOWS);
            hash(meta.hash2, HashAlgorithm.crc32, (bit<16>)0, {hdr.ethernet.dstAddr}, (bit<32>)MAX_FLOWS);

            // Use either meta.hash1 or meta.hash2, depending on the situation, to read or write to the
            // mac_intf_table. Basically, meta.hash1 and meta.hash2 are indices to the mac_intf_table. 


            ##### YOUR CODE HERE - START #####

            // HINT:  You need less than 10 lines of code here.
            //
            // 1. First, take note of a MAC address of the packet and which interface the packet used 
            // to enter the switch, and save this to the hash table, mac_intf_table.
            //
            // Should you use the source or destination MAC? 
            // In other words, should use use meta.hash1 or meta.hash2 when finding an entry
            // to save the information of the incoming interface for that MAC? 
            // You should select the right one. 
            //
            // Hint: Recap on self-learning L2 switch, the class on Wed, March 27.
            //   Note that we are not using ARP packets here though.
            //
            // Hint: the variable "standard_metadata.ingress_port" holds the interface number
            // which the packet used to enter the switch. 
            //
            // Hint: If stuck, check other excercises in the previous directory that use a register (i.e., hashtable)
            //       (e.g., link monitor)
            //
            // 2. Okay, information saved. Next, check if the switch knows where 
            // this packet should go out (which interface to use) to reach its 
            // destination based on the MAC address. 
            //
            // When looking up the hashtable, should you use meta.hash1 or meta.hash2? 
            // You should select the right one. 
            // 
            // 3. Set the output port ("standard_metadata.egress_spec") 
            // to the value you found in the hashtable. 
            // The hashtable returns 0 if an entry is not found
            // (and standard_metadata.egress_spec=0 
            // means the packet is dropped).
            

            ##### YOUR CODE HERE - END   #####
        }


        // Apply the firewall match-action table
        // ### Look at the "s1-runtime.json" file to 
        // ### to learn what is installed in this match-action table.
        // ### Also look at the "topology.json" file to learn the
        // ### network topology and IP and MAC addresses assigned
        // ### to each host
        // ### Important for answering Quiz 3.
        firewall_table.apply();
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
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.icmp);
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
