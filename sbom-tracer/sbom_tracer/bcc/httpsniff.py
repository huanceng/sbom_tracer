#!/usr/bin/python
from __future__ import print_function

import binascii
import json
import os
import socket
import time

from sbom_tracer.util.compat import decode

try:
    from bcc import BPF
except ImportError:
    from bpfcc import BPF

prog = """
#ifndef KBUILD_MODNAME
#define KBUILD_MODNAME "bcc"
#endif

#ifndef BPF_SK_LOOKUP
#define BPF_SK_LOOKUP 36
#endif

enum bpf_link_type {
        BPF_LINK_TYPE_UNSPEC = 0,
        BPF_LINK_TYPE_RAW_TRACEPOINT = 1,
        BPF_LINK_TYPE_TRACING = 2,
        BPF_LINK_TYPE_CGROUP = 3,
        BPF_LINK_TYPE_ITER = 4,
        BPF_LINK_TYPE_NETNS = 5,
        BPF_LINK_TYPE_XDP = 6,
        BPF_LINK_TYPE_PERF_EVENT = 7,
        BPF_LINK_TYPE_KPROBE_MULTI = 8,
        BPF_LINK_TYPE_STRUCT_OPS = 9,
        MAX_BPF_LINK_TYPE,
};

#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>

#define IP_TCP  6
#define ETH_HLEN 14

struct Key {
        u32 src_ip;               //source ip
        u32 dst_ip;               //destination ip
        unsigned short src_port;  //source port
        unsigned short dst_port;  //destination port
};

struct Leaf {
        int timestamp;            //timestamp in ns
};

//BPF_TABLE(map_type, key_type, leaf_type, table_name, num_entry)
//map <Key, Leaf>
//tracing sessions having same Key(dst_ip, src_ip, dst_port,src_port)
BPF_HASH(sessions, struct Key, struct Leaf, 1024);

/*eBPF program.
  Filter IP and TCP packets, having payload not empty
  and containing "HTTP", "GET", "POST"  as first bytes of payload.
  AND ALL the other packets having same (src_ip,dst_ip,src_port,dst_port)
  this means belonging to the same "session"
  this additional check avoids url truncation, if url is too long
  userspace script, if necessary, reassembles urls splitted in 2 or more packets.
  if the program is loaded as PROG_TYPE_SOCKET_FILTER
  and attached to a socket
  return  0 -> DROP the packet
  return -1 -> KEEP the packet and return it to user space (userspace can read it from the socket_fd )
*/
int http_filter(struct __sk_buff *skb) {

        u8 *cursor = 0;

        struct ethernet_t *ethernet = cursor_advance(cursor, sizeof(*ethernet));
        //filter IP packets (ethernet type = 0x0800)
        if (!(ethernet->type == 0x0800)) {
                goto DROP;
        }

        struct ip_t *ip = cursor_advance(cursor, sizeof(*ip));
        //filter TCP packets (ip next protocol = 0x06)
        if (ip->nextp != IP_TCP) {
                goto DROP;
        }

        u32  tcp_header_length = 0;
        u32  ip_header_length = 0;
        u32  payload_offset = 0;
        u32  payload_length = 0;
        struct Key      key;
        struct Leaf zero = {0};

        //calculate ip header length
        //value to multiply * 4
        //e.g. ip->hlen = 5 ; IP Header Length = 5 x 4 byte = 20 byte
        ip_header_length = ip->hlen << 2;    //SHL 2 -> *4 multiply

        //check ip header length against minimum
        if (ip_header_length < sizeof(*ip)) {
                goto DROP;
        }

        //shift cursor forward for dynamic ip header size
        void *_ = cursor_advance(cursor, (ip_header_length-sizeof(*ip)));

        struct tcp_t *tcp = cursor_advance(cursor, sizeof(*tcp));

        //retrieve ip src/dest and port src/dest of current packet
        //and save it into struct Key
        key.dst_ip = ip->dst;
        key.src_ip = ip->src;
        key.dst_port = tcp->dst_port;
        key.src_port = tcp->src_port;

        //calculate tcp header length
        //value to multiply *4
        //e.g. tcp->offset = 5 ; TCP Header Length = 5 x 4 byte = 20 byte
        tcp_header_length = tcp->offset << 2; //SHL 2 -> *4 multiply

        //calculate payload offset and length
        payload_offset = ETH_HLEN + ip_header_length + tcp_header_length;
        payload_length = ip->tlen - ip_header_length - tcp_header_length;

        //http://stackoverflow.com/questions/25047905/http-request-minimum-size-in-bytes
        //minimum length of http request is always greater than 7 bytes
        //avoid invalid access memory
        //include empty payload
        if(payload_length < 7) {
                goto DROP;
        }

        //load first 7 byte of payload into p (payload_array)
        //direct access to skb not allowed
        unsigned long p[7];
        int i = 0;
        for (i = 0; i < 7; i++) {
                p[i] = load_byte(skb , payload_offset + i);
        }

        //find a match with an HTTP message
        //GET
        if ((p[0] == 'G') && (p[1] == 'E') && (p[2] == 'T')) {
                goto HTTP_MATCH;
        }
        //POST
        if ((p[0] == 'P') && (p[1] == 'O') && (p[2] == 'S') && (p[3] == 'T')) {
                goto HTTP_MATCH;
        }
        //PUT
        if ((p[0] == 'P') && (p[1] == 'U') && (p[2] == 'T')) {
                goto HTTP_MATCH;
        }
        //HEAD
        if ((p[0] == 'H') && (p[1] == 'E') && (p[2] == 'A') && (p[3] == 'D')) {
                goto HTTP_MATCH;
        }

        //no HTTP match
        //check if packet belong to an HTTP session
        struct Leaf * lookup_leaf = sessions.lookup(&key);
        if(lookup_leaf) {
                //send packet to userspace
                goto KEEP;
        }
        goto DROP;

        //keep the packet and send it to userspace returning -1
        HTTP_MATCH:
        //if not already present, insert into map <Key, Leaf>
        sessions.lookup_or_init(&key,&zero);

        //send packet to userspace returning -1
        KEEP:
        return -1;

        //drop the packet returning 0
        DROP:
        return 0;

}
"""

CLEANUP_N_PACKETS = 50  # run cleanup every CLEANUP_N_PACKETS packets received
MAX_URL_STRING_LEN = 8192  # max url string len (usually 8K)
MAX_AGE_SECONDS = 30  # max age entry in bpf_sessions map


# cleanup function
def cleanup():
    # get current time in seconds
    current_time = int(time.time())
    # looking for leaf having:
    # timestap  == 0        --> update with current timestamp
    # AGE > MAX_AGE_SECONDS --> delete item
    for key, leaf in bpf_sessions.items():
        try:
            current_leaf = bpf_sessions[key]
            # set timestamp if timestamp == 0
            if current_leaf.timestamp == 0:
                bpf_sessions[key] = bpf_sessions.Leaf(current_time)
            else:
                # delete older entries
                if current_time - current_leaf.timestamp > MAX_AGE_SECONDS:
                    del bpf_sessions[key]
        except:
            pass


# arguments
interface = "eth0"

bpf = BPF(text=prog)

# load eBPF program http_filter of type SOCKET_FILTER into the kernel eBPF vm
# more info about eBPF program types
# http://man7.org/linux/man-pages/man2/bpf.2.html
function_http_filter = bpf.load_func("http_filter", BPF.SOCKET_FILTER)

# create raw socket, bind it to interface
# attach bpf program to socket created
BPF.attach_raw_socket(function_http_filter, interface)

# get file descriptor of the socket previously created inside BPF.attach_raw_socket
socket_fd = function_http_filter.sock

# create python socket object, from the file descriptor
sock = socket.fromfd(socket_fd, socket.PF_PACKET, socket.SOCK_RAW, socket.IPPROTO_IP)
# set it as blocking socket
sock.setblocking(True)

# get pointer to bpf map of type hash
bpf_sessions = bpf.get_table("sessions")

# packets counter
packet_count = 0

# dictionary containing association <key(ipsrc,ipdst,portsrc,portdst),payload_string>
# if url is not entirely contained in only one packet, save the firt part of it in this local dict
# when I find \r\n in a next pkt, append and print all the url
local_dictionary = {}

while 1:
    # retrieve raw packet from socket
    packet_str = os.read(socket_fd, 4096)  # set packet length to max packet length on the interface
    packet_count += 1

    # convert packet into bytearray
    packet_bytearray = bytearray(packet_str)

    # ethernet header length
    ETH_HLEN = 14

    # IP HEADER
    # https://tools.ietf.org/html/rfc791
    # 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |Version|  IHL  |Type of Service|          Total Length         |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #
    # IHL : Internet Header Length is the length of the internet header
    # value to multiply * 4 byte
    # e.g. IHL = 5 ; IP Header Length = 5 * 4 byte = 20 byte
    #
    # Total length: This 16-bit field defines the entire packet size,
    # including header and data, in bytes.

    # calculate packet total length
    total_length = packet_bytearray[ETH_HLEN + 2]  # load MSB
    total_length = total_length << 8  # shift MSB
    total_length = total_length + packet_bytearray[ETH_HLEN + 3]  # add LSB

    # calculate ip header length
    ip_header_length = packet_bytearray[ETH_HLEN]  # load Byte
    ip_header_length = ip_header_length & 0x0F  # mask bits 0..3
    ip_header_length = ip_header_length << 2  # shift to obtain length

    # retrieve ip source/dest
    ip_src_str = packet_str[ETH_HLEN + 12:ETH_HLEN + 16]  # ip source offset 12..15
    ip_dst_str = packet_str[ETH_HLEN + 16:ETH_HLEN + 20]  # ip dest   offset 16..19

    ip_src = int(binascii.hexlify(ip_src_str), 16)
    ip_dst = int(binascii.hexlify(ip_dst_str), 16)

    # TCP HEADER
    # https://www.rfc-editor.org/rfc/rfc793.txt
    #  12              13              14              15
    #  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |  Data |           |U|A|P|R|S|F|                               |
    # | Offset| Reserved  |R|C|S|S|Y|I|            Window             |
    # |       |           |G|K|H|T|N|N|                               |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #
    # Data Offset: This indicates where the data begins.
    # The TCP header is an integral number of 32 bits long.
    # value to multiply * 4 byte
    # e.g. DataOffset = 5 ; TCP Header Length = 5 * 4 byte = 20 byte

    # calculate tcp header length
    tcp_header_length = packet_bytearray[ETH_HLEN + ip_header_length + 12]  # load Byte
    tcp_header_length = tcp_header_length & 0xF0  # mask bit 4..7
    tcp_header_length = tcp_header_length >> 2  # SHR 4 ; SHL 2 -> SHR 2

    # retrieve port source/dest
    port_src_str = packet_str[ETH_HLEN + ip_header_length:ETH_HLEN + ip_header_length + 2]
    port_dst_str = packet_str[ETH_HLEN + ip_header_length + 2:ETH_HLEN + ip_header_length + 4]

    port_src = int(binascii.hexlify(port_src_str), 16)
    port_dst = int(binascii.hexlify(port_dst_str), 16)

    # calculate payload offset
    payload_offset = ETH_HLEN + ip_header_length + tcp_header_length

    # payload_string contains only packet payload
    payload_string = packet_str[payload_offset:(len(packet_bytearray))]

    # CR + LF (substring to find)
    crlf = b"\r\n"

    # current_Key contains ip source/dest and port source/map
    # useful for direct bpf_sessions map access
    current_Key = bpf_sessions.Key(ip_src, ip_dst, port_src, port_dst)

    # looking for HTTP GET/POST request
    if ((payload_string[:3] == "GET") or (payload_string[:4] == "POST") or (payload_string[:3] == "PUT")
            or (payload_string[:4] == "HEAD")):
        # match: HTTP GET/POST packet found
        if crlf in payload_string:
            # url entirely contained in first packet -> print it all
            print(json.dumps(dict(data=decode(payload_string))))

            # delete current_Key from bpf_sessions, url already printed. current session not useful anymore
            try:
                del bpf_sessions[current_Key]
            except:
                pass
        else:
            # url NOT entirely contained in first packet
            # not found \r\n in payload.
            # save current part of the payload_string in dictionary <key(ips,ipd,ports,portd),payload_string>
            local_dictionary[binascii.hexlify(current_Key)] = payload_string
    else:
        # NO match: HTTP GET/POST  NOT found

        # check if the packet belong to a session saved in bpf_sessions
        if current_Key in bpf_sessions:
            # check id the packet belong to a session saved in local_dictionary
            # (local_dictionary mantains HTTP GET/POST url not printed yet because splitted in N packets)
            if binascii.hexlify(current_Key) in local_dictionary:
                # first part of the HTTP GET/POST url is already present in local dictionary (prev_payload_string)
                prev_payload_string = local_dictionary[binascii.hexlify(current_Key)]
                # looking for CR+LF in current packet.
                if crlf in payload_string:
                    # last packet. containing last part of HTTP GET/POST url splitted in N packets.
                    # append current payload
                    prev_payload_string += payload_string
                    # print HTTP GET/POST url
                    print(json.dumps(dict(data=decode(prev_payload_string))))
                    # clean bpf_sessions & local_dictionary
                    try:
                        del bpf_sessions[current_Key]
                        del local_dictionary[binascii.hexlify(current_Key)]
                    except:
                        pass
                else:
                    # NOT last packet. containing part of HTTP GET/POST url splitted in N packets.
                    # append current payload
                    prev_payload_string += payload_string
                    # check if not size exceeding (usually HTTP GET/POST url < 8K )
                    if len(prev_payload_string) > MAX_URL_STRING_LEN:
                        try:
                            del bpf_sessions[current_Key]
                            del local_dictionary[binascii.hexlify(current_Key)]
                        except:
                            pass
                    # update dictionary
                    local_dictionary[binascii.hexlify(current_Key)] = prev_payload_string
            else:
                # first part of the HTTP GET/POST url is NOT present in local dictionary
                # bpf_sessions contains invalid entry -> delete it
                try:
                    del bpf_sessions[current_Key]
                except:
                    pass

    # check if dirty entry are present in bpf_sessions
    if (packet_count % CLEANUP_N_PACKETS) == 0:
        cleanup()
