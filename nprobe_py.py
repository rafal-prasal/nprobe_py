#!/usr/bin/env python3

# Copyright 2024 Rafal Prasal <rafal.prasal@gmail.com>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import socket
import os
import sys
import time
import zmq
import multiprocessing as mp
import json
import zlib
import ipaddress
import argparse
import re

#https://stackoverflow.com/questions/107705/disable-output-buffering
buf_arg = 0
if sys.version_info[0] == 3:
    os.environ['PYTHONUNBUFFERED'] = '1'
    buf_arg = 1

sys.stdout = os.fdopen(sys.stdout.fileno(), 'w', buf_arg)
sys.stderr = os.fdopen(sys.stderr.fileno(), 'w', buf_arg)

#https://www.rfc-editor.org/rfc/rfc5102.html

def unknown(bytes):
    return '0x'+str(bytes.hex())

def unsigned(bytes):
    return int.from_bytes(bytes, 'big')

def macaddress(bytes):
    mac=str(hex(int.from_bytes(bytes, 'big')))
    return mac[2:4]+':'+mac[4:6]+':'+mac[6:8]+':'+mac[8:10]+':'+mac[10:12]+':'+mac[12:14]

def ipv4address(bytes):
    return ipaddress.IPv4Address(bytes).exploded
    
def ipv6address(bytes):
    return ipaddress.IPv6Address(bytes).exploded

fields = {
    0:  { 
        'name': 'reserved',
        'from_bytes': unknown,
    },

    1:  { 
        'name': 'octetDeltaCount',
        'from_bytes': unsigned,
        'nprobe': 'IN_BYTES'
    },

    2:  {
        'name': 'packetDeltaCount',
        'from_bytes': unsigned,
        'nprobe': 'IN_PKTS'
    },

    3:  {
        'name': 'reserved',
        'from_bytes': unknown
    },

    4:  {
        'name': 'protocolIdentifier',
        'from_bytes': unsigned,
        'nprobe': 'PROTOCOL'
    },

    5:  {
        'name': 'ipClassOfService',
        'from_bytes': unsigned,
        'nprobe': 'SRC_TOS'
    },

    6:  {
        'name': 'tcpControlBits',
        'from_bytes': unsigned,
        'nprobe': 'TCP_FLAGS'
    },

    7:  {
        'name': 'sourceTransportPort',
        'from_bytes': unsigned,
        'nprobe': 'L4_SRC_PORT'
    },

    8:  {
        'name': 'sourceIPv4Address',
        'from_bytes': ipv4address,
        'nprobe': 'IPV4_SRC_ADDR'
    },

    9:  {
        'name': 'sourceIPv4PrefixLength',
        'from_bytes': unsigned,
        'nprobe': 'IPV4_SRC_MASK'
    },

    10: {
        'name': 'ingressInterface',
        'from_bytes': unsigned,
        'nprobe': 'INPUT_SNMP'
    },

    11: {
        'name': 'destinationTransportPort',
        'from_bytes': unsigned,
        'nprobe': 'L4_DST_PORT'
    },
   
    12: {
        'name': 'destinationIPv4Address',
        'from_bytes': ipv4address,
        'nprobe': 'IPV4_DST_ADDR'
    },
    13: {
        'name': 'destinationIPv4PrefixLength',
        'from_bytes': unsigned,
        'nprobe': 'IPV4_DST_MASK'
    },

    14: {
        'name': 'egressInterface',
        'from_bytes': unsigned,
        'nprobe': 'OUTPUT_SNMP'
    },

    15: {
        'name': 'ipNextHopIPv4Address',
        'from_bytes': ipv4address,
        'nprobe': 'IPV4_NEXT_HOP'
    },

    16: {
        'name': 'bgpSourceAsNumber',
        'from_bytes': unsigned,
        'nprobe': 'SRC_AS'
        },

    17: {
        'name': 'DST_AS',
        'from_bytes': unsigned,
        'nprobe': 'DST_AS'
    },

    18: {
        'name': 'bgpNexthopIPv4Address',
        'from_bytes': ipv4address,
        'nprobe': 'BGP_IPV4_NEXT_HOP'
    },

    21: {
        'name': 'flowEndSysUpTime',
        'from_bytes': unsigned,
        'nprobe': 'LAST_SWITCHED'
    },

    22: {
        'name': 'flowStartSysUpTime',
        'from_bytes': unsigned,
        'nprobe': 'FIRST_SWITCHED'
    },

    27: {
        'name': 'sourceIPv6Address',
        'from_bytes': ipv6address,
        'nprobe': 'IPV6_SRC_ADDR'
    },

    28: {
        'name': 'destinationIPv6Address',
        'from_bytes': ipv6address,
        'nprobe': 'IPV6_DST_ADDR'
    },

    29: {
        'name': 'sourceIPv6PrefixLength',
        'from_bytes': unsigned,
        'nprobe': 'IPV6_SRC_MASK'
    },

    30: {
        'name': 'destinationIPv6PrefixLength',
        'from_bytes': unsigned,
        'nprobe': 'IPV6_DST_MASK'
    },

    31: {
        'name': 'flowLabelIPv6',
        'from_bytes': unknown
    },

    32: {
        'name':  'icmpTypeCodeIPv4',
        'from_bytes': unsigned,
        'nprobe': 'ICMP_TYPE'
    },


    33: {
        'name': 'igmpType',
        'from_bytes': unsigned
    },

    34: {
        'name': 'SAMPLING_INTERVAL',
        'from_bytes': unsigned,
        'nprobe': 'SAMPLING_INTERVAL'
    },

    35: {
        'name': 'SAMPLING_ALGORITHM',
        'from_bytes': unsigned,
        'nprobe': 'SAMPLING_ALGORITHM'
    },

    36: {
        'name': 'flowActiveTimeout',
        'from_bytes': unsigned,
        'nprobe': 'FLOW_ACTIVE_TIMEOUT'
    },

    37: {
        'name': 'flowIdleTimeout',
        'from_bytes': unsigned,
        'nprobe': 'FLOW_INACTIVE_TIMEOUT'
    },


    38: {
        'name': 'ENGINE_TYPE',
        'from_bytes': unsigned,
        'nprobe': 'ENGINE_TYPE'
    },

    39: {
        'name': 'ENGINE_ID',
        'from_bytes': unsigned,
        'nprobe': 'ENGINE_ID'
    },

    40: {
        'name': 'exportedOctetTotalCount',
        'from_bytes': unsigned,
        'nprobe': 'TOTAL_BYTES_EXP'
    },

    41: {
        'name': 'exportedMessageTotalCount',
        'from_bytes': unsigned,
        'nprobe': 'TOTAL_PKTS_EXP'
    },

    42: {
        'name': 'exportedFlowRecordTotalCount',
        'from_bytes': unsigned,
        'nprobe': 'TOTAL_FLOWS_EXP'
    },

    52: {
        'name': 'minimumTTL',
        'from_bytes': unsigned,
        'nprobe': 'TOTAL_FLOWS_EXP'
    },

    53: {
        'name': 'MIN_TTL',
        'from_bytes': unsigned,
        'nprobe': 'MAX_TTL'
    },

    55: {
        'name': 'ipClassOfService',
        'from_bytes': unsigned,
        'nprobe': 'DST_TOS'
    },

    56: {
         'name': 'sourceMacAddress',
         'from_bytes': macaddress,
         'nprobe': 'IN_SRC_MAC'
    },

    57: {
         'name': 'postDestinationMacAddress',
         'from_bytes': macaddress,
         'nprobe': 'OUT_DST_MAC'
    },

    58: {
         'name': 'vlanId',
         'from_bytes': unsigned,
         'nprobe': 'SRC_VLAN'
    },

    59: {
         'name': 'postVlanId',
         'from_bytes': unsigned,
         'nprobe': 'DST_VLAN'
    },

    60: {
         'name': 'ipVersion',
         'from_bytes': unsigned,
         'nprobe': 'IP_PROTOCOL_VERSION'
    },
    61: {
        'name': 'flowDirection',
        'from_bytes': unsigned,
        'nprobe': 'DIRECTION'
    },

    62: {
        'name': 'ipNextHopIPv6Address',
        'from_bytes': ipv6address,
        'nprobe': 'IPV6_NEXT_HOP'
    },

    70: {
        'name': 'mplsTopLabelStackSection',
        'from_bytes': unsigned,
        'nprobe': 'MPLS_LABEL_1'
    },

    71: {
        'name': 'mplsLabelStackSection2',
        'from_bytes': unsigned,
        'nprobe': 'MPLS_LABEL_2'
    },

    72: {
        'name': 'mplsLabelStackSection3',
        'from_bytes': unsigned,
        'nprobe': 'MPLS_LABEL_3'
    },

    73: {
        'name': 'mplsLabelStackSection4',
        'from_bytes': unsigned,
        'nprobe': 'MPLS_LABEL_4'
    },

    74: {
        'name': 'mplsLabelStackSection5',
        'from_bytes': unsigned,
        'nprobe': 'MPLS_LABEL_5'
    },

    75: {
        'name': 'mplsLabelStackSection6',
        'from_bytes': unsigned,
        'nprobe': 'MPLS_LABEL_6'
    },

    76: {
        'name': 'mplsLabelStackSection7',
        'from_bytes': unsigned,
        'nprobe': 'MPLS_LABEL_7'
    },

    77: {
        'name': 'mplsLabelStackSection8',
        'from_bytes': unsigned,
        'nprobe': 'MPLS_LABEL_8'
    },

    78: {
        'name': 'mplsLabelStackSection9',
        'from_bytes': unsigned,
        'nprobe': 'MPLS_LABEL_9'
    },

    79: {
        'name': 'mplsLabelStackSection10',
        'from_bytes': unsigned,
        'nprobe': 'MPLS_LABEL_10'
    },

    80: { 
        'name': 'destinationMacAddress',
        'from_bytes': macaddress,
        'nprobe': 'IN_DST_MACADDRESS'
    },

    81: {
        'name': 'postSourceMacAddress',
        'from_bytes': macaddress,
        'nprobe': 'OUT_SRC_MAC'
    },

    82: { 
        'name': 'interfaceName',
        'from_bytes': str,
        'nprobe': 'INTERFACE_NAME'
    },

    95: { 
        'name': 'application_id',
        'from_bytes': unsigned,
        'nprobe': 'APPLICATION_ID'
    },

    102: {
        'name': 'PACKET_SECTION_OFFSET',
        'from_bytes': unsigned,
        'nprobe': 'PACKET_SECTION_OFFSET'
    },

    103: {
        'name': 'SAMPLED_PACKET_SIZE',
        'from_bytes': unsigned,
        'nprobe': 'SAMPLED_PACKET_SIZE'
    },

    104: {
        'name': 'SAMPLED_PACKET_ID',
        'from_bytes': unsigned,
        'nprobe': 'SAMPLED_PACKET_ID'
    },

    130: {
        'nprobe': 'EXPORTER_IPV4_ADDRESS',
        'from_bytes': ipv4address,
        'name': 'exporterIPv4Address'
    },

    131: {
        'nprobe': 'EXPORTER_IPV6_ADDRESS',
        'from_bytes': ipv6address,
        'name': 'exporterIPv6Address'
    },

    148: {
        'name': 'flowId',
        'from_bytes': unsigned,
        'nprobe': 'FLOW_ID'
    },

    150: {
        'name': 'flowStartSeconds',
        'from_bytes': unsigned,
        'nprobe': 'FLOW_START_SEC'
    },

    151: {
        'name': 'flowEndSeconds',
        'from_bytes': unsigned,
        'nprobe': 'FLOW_END_SEC'
    },

    152: {
        'name': 'flowStartMilliseconds',
        'from_bytes': unsigned,
        'nprobe': 'FLOW_START_MILLISECONDS'
    },

    153: {
        'name': 'flowEndMilliseconds',
        'from_bytes': unsigned,
        'nprobe': 'FLOW_END_MILLISECONDS'
    },

    154: {
        'name': 'flowStartMicroseconds',
        'from_bytes': unsigned,
        'nprobe': 'FLOW_START_MILLISECONDS'
    },

    155: {
        'name': 'flowEndMicroseconds',
        'from_bytes': unsigned,
        'nprobe': 'FLOW_END_MICROSECONDS'
    },

    160: { 
        'name': 'systemInitTimeMilliseconds',
        'from_bytes': unsigned,
	},

    161: {
        'name': 'flowDurationMilliseconds',
        'from_bytes': unsigned,
        'nprobe': 'FLOW_DURATION_MILLISECONDS'
    },

    162: {
        'name': 'flowDurationMicroseconds',
        'from_bytes': unsigned,
        'nprobe': 'FLOW_DURATION_MICROSECONDS'
    },


    176: {
        'name': 'icmpTypeIPv4',
        'from_bytes': unsigned,
        'nprobe': 'ICMP_IPV4_TYPE'
    },

    177: {
        'name': 'icmpCodeIPv4', 
        'from_bytes': unsigned,
        'nprobe': 'ICMP_IPV4_TYPE'

    },

    178: {
        'name': 'icmpTypeIPv6',
        'from_bytes': unknown
    },
    
    179: {
        'name': 'icmpCodeIPv6',
        'from_bytes': unknown
    },

    184: { 'name': 'tcpSequenceNumber',
           'from_bytes': unsigned
    },

    185: { 'name': 'tcpAcknowledgementNumber', 
           'from_bytes': unsigned
    },

    186: { 'name': 'tcpWindowSize',
           'from_bytes': unsigned
    },

    189: { 'name': 'ipHeaderLength',
           'from_bytes': unsigned,
    },

    192: { 'name': 'ipTTL',
           'from_bytes': unsigned,
    },

    205: { 'name': 'udpMessageLength',
           'from_bytes': unsigned,
    },

    206: { 'name': 'isMulticast',
           'from_bytes': unsigned
    },

    224: {
         'name': 'ipTotalLength',
         'from_bytes': unsigned
    },

    225: {
         'name': 'postNATSourceIPv4Address',
         'from_bytes': ipv4address,
         'nprobe': 'POST_NAT_SRC_IPV4_ADDR'
    },

    226: {
         'name': 'postNATDestinationIPv4Address',
         'from_bytes': ipv4address,
         'nprobe': 'POST_NAT_DST_IPV4_ADDR'
    },

    227: {
         'name': 'postNAPTSourceTransportPort',
         'from_bytes': unsigned,
         'nprobe': 'POST_NAPT_SRC_TRANSPORT_PORT'
    },

    228: {
        'name': 'postNAPTDestinationTransportPort',
        'from_bytes': unsigned,
        'nprobe': 'POST_NAPT_DST_TRANSPORT_PORT'
    },

    229: {
        'name': 'natOriginatingAddressRealm',
        'from_bytes': unsigned,
        'nprobe': 'NAT_ORIGINATING_ADDRESS_REALM'
    },

    230: {
        'name': 'natEvent',
        'from_bytes': unsigned,
        'nprobe': 'NAT_EVENT'
    },

    233: {
        'name': 'firewallEvent',
        'from_bytes': unsigned,
        'nprobe': 'FIREWALL_EVENT'
    },

    234: {
        'name': 'ingressVRFID',
        'from_bytes': unsigned,
        'nprobe': 'INGRESS_VRFID'
    },

    239: {
        'name': 'biflow_direction',
        'from_bytes': unsigned,
        'nprobe': 'BIFLOW_DIRECTION'
    },

    243: {
        'name': 'dot1qVlanId',
        'from_bytes': unsigned,
        'nprobe': 'DOT1Q_SRC_VLAN'
    },

    254: {
        'name': 'postdot1qVlanId',
        'from_bytes': unsigned,
        'nprobe': 'DOT1Q_DST_VLAN'
    },

    277: {
        'name': 'OBSERVATION_POINT_TYPE',
        'from_bytes': unsigned,
        'nprobe': 'OBSERVATION_POINT_TYPE'
    },

    300: {
        'name': 'OBSERVATION_POINT_ID',
        'from_bytes': unsigned,
        'nprobe': 'OBSERVATION_POINT_ID'
    },

    302: {
        'name': 'SELECTOR_ID',
        'from_bytes': unsigned,
        'nprobe': 'SELECTOR_ID'
    },

    304: {
        'name': 'IPFIX_SAMPLING_ALGORITHM',
        'from_bytes': unsigned,
        'nprobe': 'IPFIX_SAMPLING_ALGORITHM'
    },

    309: {
        'name': 'SAMPLING_SIZE',
        'from_bytes': unsigned,
        'nprobe': 'SAMPLING_SIZE'
    },

    310: {
        'name': 'SAMPLING_POPULATION',
        'from_bytes': unsigned,
        'nprobe': 'SAMPLING_POPULATION'
    },


    312: {
        'name': 'FRAME_LENGTH',
        'from_bytes': unsigned,
        'nprobe': 'FRAME_LENGTH'
    },

    318: {
        'name': 'PACKETS_OBSERVED',
        'from_bytes': unsigned,
        'nprobe': 'PACKETS_OBSERVED'
    },

    319: {
        'name': 'PACKETS_SELECTED',
        'from_bytes': unsigned,
        'nprobe': 'PACKETS_SELECTED'
    },

    335: {
        'name': 'SELECTOR_NAME',
        'from_bytes': unsigned,
        'nprobe': 'SELECTOR_NAME'
    },
}

def parseAddress(address):
    m=re.match('^udp:\/\/([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}):([0-9]+)$', address)

    if m is None:
        raise Exception(address +" not in format +udp://IPv4:port")

    ipv4=ipaddress.IPv4Address(m.group(1)).exploded
    port=int(m.group(2))

    return  (ipv4, port)

def netflow_collector(args_collector_port, args_verbose, args_performance, q):
    templates={}
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    server_socket.bind( parseAddress(args_collector_port) ) 

    print("Netflow: loop")

    pkt_cnt=0

    while True:
        message, address = server_socket.recvfrom(1500)
        start_processing=time.time_ns()

        msg_version = int.from_bytes(message[0:2], 'big')

        if msg_version != 10:
            print("#WARNING: unknown version "+str(msg_version))
            continue

        msg_length  = int.from_bytes(message[2:4],'big')
        msg_export_time = int.from_bytes(message[4:8],'big')
        msg_sequence_number = int.from_bytes(message[8:12],'big')
        msg_observation_domain_id = int.from_bytes(message[12:16],'big')

        print('NetFlow:'+str(pkt_cnt)+' ver:'+str(msg_version)+' seq:'+str(msg_sequence_number)+' dom:'+str(msg_observation_domain_id))

        data_offset=16
        while(data_offset<msg_length):
            records = []

            set_id=int.from_bytes(message[data_offset:data_offset+2],'big')
            set_length=int.from_bytes(message[data_offset+2:data_offset+4],'big')

            set_offset=data_offset+4
            print('NetFlow:'+str(pkt_cnt)+' set:'+str(set_id)+' len:'+str(set_length))

            if set_id == 2:
                rec_offset=set_offset
                while(rec_offset<data_offset+set_length):
                    template_id=int.from_bytes(message[rec_offset:rec_offset+2],'big')
                    field_count=int.from_bytes(message[rec_offset+2:rec_offset+4],'big')

                    print('NetFlow:'+ str(pkt_cnt)+ ' tpl:'+str(template_id)+' num:' + str(field_count))

                    if field_count==0:
                       del templates[template_id]
                       set_offset=set_offset+4
                       continue

                    field_list=[]
                    field_offset=rec_offset+4

                    rec_len=0
                    for i in range(field_count):
                        field_id=int.from_bytes(message[field_offset:field_offset+2],'big')
                        field_length=int.from_bytes(message[field_offset+2:field_offset+4],'big')
                        field_enterprise=None

                        if field_id & 0x8000:
                            field_enterprise = int.from_bytes(message[field_offset+4:field_offset+8],'big')
                            field_offset=field_offset+4
                      
                        rec_len=rec_len+field_length

                        field_list.append((field_id, field_length, field_enterprise))

                        field_offset=field_offset+4

                    templates[ template_id ] = {
                         'fields': field_list,
                         'length': rec_len
                    }

                    rec_offset=field_offset
                set_offset=rec_offset

            elif set_id in templates:
                rec_offset=set_offset
                field_offset=rec_offset

                while (rec_offset<data_offset+set_length):
                    record = {}
                    for f in templates[set_id]['fields']:
                        (field_id, field_length, field_enterprise) = f

                        if 'nprobe' in fields[field_id]:
                            record[ fields[field_id]['nprobe'] ] = fields[field_id]['from_bytes'](
                                                            message[field_offset:field_offset+field_length]
                                                        )
        
                        field_offset=field_offset+field_length

                    records.append(record)

                    rec_offset=field_offset
                set_offset=rec_offset

            end_processing = time.time_ns()

            if(len(records)>0):
                q.put(records)

            end_queueing = time.time_ns()

            pkt_cnt=pkt_cnt+1
            data_offset=data_offset+set_length

            if args_performance:
                print("netflow_timers(ns) " \
                    +str(end_queueing-start_processing) \
                    +" / " \
                    +str(end_processing-start_processing) \
                    +" / " \
                    +str(end_queueing-end_processing)
                )

def zmq_broker(args_ntopng, args_zmq_disable_compression, args_verbose, args_performance, q):

    context = zmq.Context.instance()
    socket = context.socket(zmq.PUB)

    socket.setsockopt(zmq.TCP_KEEPALIVE,1)
    socket.setsockopt(zmq.TCP_KEEPALIVE_CNT,30)
    socket.setsockopt(zmq.TCP_KEEPALIVE_IDLE,3)
    socket.setsockopt(zmq.TCP_KEEPALIVE_INTVL,3)

    socket.bind(args_ntopng.replace('zmq','tcp'))

    poller = zmq.Poller()
    poller.register(socket, zmq.POLLIN | zmq.POLLOUT)

    socks = dict(poller.poll())
    assert socks[socket] == zmq.POLLOUT
    assert poller not in socks

    version=2

    zmq_msg_hdr_v2={
        'url': bytearray([ 102 ,108,111,119,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]),
        'version': version.to_bytes(4,'little'),
        'size': bytearray([0, 0, 0, 0]),
        'msg_id': 0,
        'source_id': bytearray([0,1,2,3])
    }

    print("ZMQ: loop")

    msg_id=0

    while True:
        records = q.get()
        start_processing=time.time_ns()

        if records is None:
            break

        rec_comp=json.dumps(records).encode('ascii')

        if not args_zmq_disable_compression:
            len_json = len(rec_comp)
            rec_comp=(0).to_bytes(1, 'big')+zlib.compress(rec_comp, 6)
            len_comp=len(rec_comp)
            print('copression: '+str(len_comp)+ ' / ' +str(len_json))

        end_compressing=time.time_ns()

        print('ZMQ:' + str(msg_id))

        zmq_msg_hdr_v2['msg_id']=msg_id.to_bytes(4,'little')

        socket.send_multipart([
            zmq_msg_hdr_v2['url']       \
            +zmq_msg_hdr_v2['version']  \
            +zmq_msg_hdr_v2['size']     \
            ,rec_comp
        ])
        msg_id=(msg_id+1) & 0xffffffff
        poller.poll()

        end_processing=time.time_ns()

        if args_performance:
            print("zmq_timers(ns) " \
                +str(end_processing-start_processing) \
                +" / " \
                +str(end_compressing-start_processing) \
                +" / " \
                +str(end_processing-end_compressing)
            )

    poller.unregister(socket)


if __name__ == '__main__':

    parser = argparse.ArgumentParser()
    parser.add_argument('--collector-port', default="udp://0.0.0.0:2055")
    parser.add_argument('--ntopng', default='zmq://0.0.0.0:1234')
    parser.add_argument('--zmq-disable-compression', action='store_true', default=False)
    parser.add_argument('--verbose', default="0")
    parser.add_argument('--performance', action='store_true', default=False)
    parser.add_argument('--version', action='store_true', default=False)

    args=parser.parse_args()

    if args.version:
        print("0.0.1")
        sys.exit(0)

    mp.set_start_method('spawn')
    rec_queue = mp.Queue()
    p=mp.Process(
        target=zmq_broker, 
        args=(
            args.ntopng,
            args.zmq_disable_compression,
            args.verbose,
            args.performance,
            rec_queue,
        )
    )

    p.start()

    try:
        netflow_collector(
            args.collector_port,
            args.verbose,
            args.performance,
            rec_queue,
        )
    except Exception as e:
        print(str(e))
        pass

    rec_queue.put(None)
    p.join()

    print("Exiting")

