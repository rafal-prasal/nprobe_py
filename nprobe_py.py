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
    0:  { 'name': 'reserved',
          'from_bytes': unknown,
    },

    1:  { 'name': 'octetDeltaCount',
          'from_bytes': unsigned,
          'nprobe': 'IN_BYTES'
    },

    2:  { 'name': 'packetDeltaCount',
          'from_bytes': unsigned,
          'nprobe': 'IN_PKTS'
    },

    3:  { 'name': 'reserved',
          'from_bytes': unknown
    },

    4:  { 'name': 'protocolIdentifier',
          'from_bytes': unsigned,
          'nprobe': 'PROTOCOL'
    },

    5:  { 'name': 'ipClassOfService',
          'from_bytes': unsigned,
    },

    6:  { 'name': 'tcpControlBits',
          'from_bytes': unsigned
    },

    7:  { 'name': 'sourceTransportPort',
          'from_bytes': unsigned,
          'nprobe': 'L4_SRC_PORT'
    },

    8:  { 'name': 'sourceIPv4Address',
          'from_bytes': ipv4address,
          'nprobe': 'IPV4_SRC_ADDR'
    },

    9:  { 'name': 'sourceIPv4PrefixLength',
          'from_bytes': unsigned

    },

    10: { 'name': 'ingressInterface',
          'from_bytes': unsigned
    },

    11: { 'name': 'destinationTransportPort',
          'from_bytes': unsigned,
          'nprobe': 'L4_DST_PORT'
    },
   
    12: { 'name': 'destinationIPv4Address',
          'from_bytes': ipv4address,
          'nprobe': 'IPV4_DST_ADDR'
    },
    13: { 'name': 'destinationIPv4PrefixLength',
          'from_bytes': unsigned
    },

    14: { 'name': 'egressInterface',
          'from_bytes': unsigned
    },

    15: { 'name': 'ipNextHopIPv4Address',
          'from_bytes': ipv4address,
    },

    21: { 'name': 'flowEndSysUpTime',
          'from_bytes': unsigned
    },

    22: { 'name': 'flowStartSysUpTime',
          'from_bytes': unsigned
    },

    27: { 'name': 'sourceIPv6Address',
          'from_bytes': ipv6address,
          'nprobe': 'IPV6_SRC_ADDR'
    },

    28: { 'name': 'destinationIPv6Address',
          'from_bytes': ipv6address,
          'nprobe': 'IPV6_DST_ADDR'
    },

    29: { 'name': 'sourceIPv6PrefixLength',
          'from_bytes': unknown,
    },

    30: { 'name': 'destinationIPv6PrefixLength',
          'from_bytes': unknown
    },

    31: { 'name': 'flowLabelIPv6',
          'from_bytes': unknown
    },

    33: { 'name': 'igmpType',
          'from_bytes': unsigned
    },

    56: { 'name': 'sourceMacAddress',
          'from_bytes': macaddress,
          'nprobe': 'IN_SRC_MAC'
    },

    57: { 'name': 'postDestinationMacAddress',
          'from_bytes': macaddress,
          'nprobe': 'OUT_DST_MAC'
    },

    60: { 'name': 'ipVersion',
          'from_bytes': unsigned,
          'nprobe': 'IP_PROTOCOL_VERSION'
    },

    62: { 'name': 'ipNextHopIPv6Address',
          'from_bytes': unknown
    },

    80: { 'name': 'destinationMacAddress',
          'from_bytes': macaddress
    },

    81: { 'name': 'postSourceMacAddress',
          'from_bytes': macaddress
    },

    160: { 'name': 'systemInitTimeMilliseconds',
          'from_bytes': unsigned
	},
    176: { 'name': 'icmpTypeIPv4',
           'from_bytes': unsigned
    },

    177: { 'name': 'icmpCodeIPv4', 
           'from_bytes': unsigned
    },

    178: { 'name': 'icmpTypeIPv6',
           'from_bytes': unknown
    },
    

    179: { 'name': 'icmpCodeIPv6',
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

    224: { 'name': 'ipTotalLength',
           'from_bytes': unsigned
    },
    225: { 'name': '???',
           'from_bytes': unsigned
    },
    226: { 'name': '???',
           'from_bytes': unsigned
    },
    227: { 'name': 'srcPORT',
           'from_bytes': unsigned
    },
    228: { 'name': 'dstPORT',
           'from_bytes': unsigned
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
                            field_entterprise=int.from_bytes(message[field_offset+4:field_offset+8],'big')
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

