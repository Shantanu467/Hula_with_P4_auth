# Copyright 2017-present Open Networking Foundation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
from queue import Queue
from abc import abstractmethod
from datetime import datetime

import grpc
from p4.v1 import p4runtime_pb2
from p4.v1 import p4runtime_pb2_grpc
from p4.tmp import p4config_pb2

MSG_LOG_MAX_LEN = 1024

#function to calculate crc 32
import binascii
# List of all active connections
connections = []

def ShutdownAllSwitchConnections():
    for c in connections:
        c.shutdown()

class SwitchConnection(object):

    def __init__(self, name=None, address='127.0.0.1:50051', device_id=0,
                 proto_dump_file=None):
        self.name = name
        self.address = address
        self.device_id = device_id
        self.p4info = None
        self.channel = grpc.insecure_channel(self.address)
        if proto_dump_file is not None:
            interceptor = GrpcRequestLogger(proto_dump_file)
            self.channel = grpc.intercept_channel(self.channel, interceptor)
        self.client_stub = p4runtime_pb2_grpc.P4RuntimeStub(self.channel)
        self.requests_stream = IterableQueue()
        self.stream_msg_resp = self.client_stub.StreamChannel(iter(self.requests_stream))
        self.proto_dump_file = proto_dump_file
        self.current_handle_id = 0
        connections.append(self)

    def hex1(self,n,l):
        # print(n,l)
        x = '%x' % (n,)
        return ('0'*( l-len(x) )) + x

    def cksum(self,values):
        res = 0;
        for a,b in values:
            val = binascii.crc32( binascii.a2b_hex(self.hex1(a,b)),res)
            res = val
        return res

    # packet out
    def PacketOut(self, packet, dry_run = False, **kwargs):
        request = p4runtime_pb2.StreamMessageRequest()
        request.packet.CopyFrom(packet)

        if dry_run:
            print("P4 Runtime WritePacketOut: ", request)
        else:
            # print("printing request ", request)
            # print("in here\n")
            self.requests_stream.put(request)
            for item in self.stream_msg_resp:
                if item.WhichOneof("update") is "packet":
                    print("Received packet in")
                    hdrType = int.from_bytes(item.packet.metadata[0].value, byteorder = "big")
                    msgType = int.from_bytes(item.packet.metadata[1].value, byteorder = "big")
                    pktDgst = int.from_bytes(item.packet.metadata[2].value, byteorder = "big")
                    print("Ack received: ", msgType)
                    if msgType == 3:
                        print("Intruder Detected!!!")
                    else:
                        # decode register
                        if hdrType == 1:
                            print("Register Auth")
                            k = item.packet.payload
                            regId = int.from_bytes(k[:4], byteorder = "big")
                            regIndex = int.from_bytes(k[4:8], byteorder = "big")
                            value = int.from_bytes(k[8:], byteorder = "big")
                            lst = [(hdrType,2),(msgType,2),(regId,8),(regIndex,8),(value,8)]
                            if self.cksum(lst) == pktDgst:
                                print("Successful validation!")
                            else:
                                print("Intruder Detected!!!")
                            print("Register ID: ", regId)
                            print("Register Index: ", regIndex)
                            print("Value: ", value)
                        # table auth
                        elif hdrType == 2:
                            # print(item.packet.payload)
                            print("Table Auth")
                            k = item.packet.payload
                            p1 = int.from_bytes(k[:1], byteorder = "big")
                            p2 = int.from_bytes(k[1:2], byteorder = "big")
                            lst = [(hdrType,2),(msgType,2),(p1,2),(p2,2)]
                            if self.cksum(lst) == pktDgst:
                                print("Successful validation of PacketIn!\nCompare the below params")
                            else:
                                print("Intruder Detected!!!")
                            print("Act Param 1: ", p1) # hula probes
                            print("Act Param 2: ", p2)

                        for meta in item.packet.metadata:
                            value=int.from_bytes(meta.value,byteorder='big')
                            print(meta.metadata_id, value)
                    return item # just one


    # Return the current handle_id generated by mc_node_create. Assumes that
    # handle_id being returned is immediately consumed.
    def getAndUpdateHandleId(self):
        self.current_handle_id += 1
        return self.current_handle_id - 1

    @abstractmethod
    def buildDeviceConfig(self, **kwargs):
        return p4config_pb2.P4DeviceConfig()

    def shutdown(self):
        self.requests_stream.close()
        self.stream_msg_resp.cancel()

    def MasterArbitrationUpdate(self, dry_run=False, **kwargs):
        request = p4runtime_pb2.StreamMessageRequest()
        request.arbitration.device_id = self.device_id
        request.arbitration.election_id.high = 0
        request.arbitration.election_id.low = 1

        if dry_run:
            print ("P4Runtime MasterArbitrationUpdate: ", request)
        else:
            self.requests_stream.put(request)
            for item in self.stream_msg_resp:
                return item # just one

    def SetForwardingPipelineConfig(self, p4info, dry_run=False, **kwargs):
        device_config = self.buildDeviceConfig(**kwargs)
        request = p4runtime_pb2.SetForwardingPipelineConfigRequest()
        request.election_id.low = 1
        request.device_id = self.device_id
        config = request.config

        config.p4info.CopyFrom(p4info)
        config.p4_device_config = device_config.SerializeToString()

        request.action = p4runtime_pb2.SetForwardingPipelineConfigRequest.VERIFY_AND_COMMIT
        if dry_run:
            print ("P4Runtime SetForwardingPipelineConfig:", request)
        else:
            self.client_stub.SetForwardingPipelineConfig(request)

    def WriteMCastEntry(self, mcast_entry, dry_run=False):
        request = p4runtime_pb2.WriteRequest()
        request.device_id = self.device_id
        request.election_id.low = 1
        update = request.updates.add()
        update.type = p4runtime_pb2.Update.INSERT
        update.entity.packet_replication_engine_entry.CopyFrom(mcast_entry)
        if dry_run:
            print ("P4Runtime Write:", request)
        else:
            self.client_stub.Write(request)

    def WriteTableEntry(self, table_entry, dry_run=False):
        request = p4runtime_pb2.WriteRequest()
        request.device_id = self.device_id
        request.election_id.low = 1
        update = request.updates.add()
        update.type = p4runtime_pb2.Update.INSERT
        update.entity.table_entry.CopyFrom(table_entry)
        if dry_run:
            print ("P4Runtime Write:", request)
        else:
            self.client_stub.Write(request)

    # This doesn't work because reading from the Packet Replication Engine (PRE)
    # is not implemented in P4 right now.
    # https://github.com/p4lang/PI/blob/d4e5aff15b3f77af578704fe03b82a15814da8f0/proto/frontend/src/device_mgr.cpp#L1772
    def ReadMCastEntries(self, mcast_grp_id=None, dry_run=False):
        request = p4runtime_pb2.ReadRequest()
        request.device_id = self.device_id
        entity = request.entities.add()
        mcast_entry = entity.packet_replication_engine_entry.multicast_group_entry
        if mcast_grp_id is not None:
            mcast_entry.multicast_group_id = mcast_grp_id
        else:
            mcast_entry.multicast_group_id = 0

        if dry_run:
            print ("P4Runtime Read:", request)
        else:
            for response in self.client_stub.Read(request):
                yield response

    def ReadTableEntries(self, table_id=None, dry_run=False):
        request = p4runtime_pb2.ReadRequest()
        request.device_id = self.device_id
        entity = request.entities.add()
        table_entry = entity.table_entry
        if table_id is not None:
            table_entry.table_id = table_id
        else:
            table_entry.table_id = 0
        if dry_run:
            print ("P4Runtime Read:", request)
        else:
            for response in self.client_stub.Read(request):
                yield response

    def ReadCounters(self, counter_id=None, index=None, dry_run=False):
        request = p4runtime_pb2.ReadRequest()
        request.device_id = self.device_id
        entity = request.entities.add()
        counter_entry = entity.counter_entry
        if counter_id is not None:
            counter_entry.counter_id = counter_id
        else:
            counter_entry.counter_id = 0
        if index is not None:
            counter_entry.index.index = index
        if dry_run:
            print( "P4Runtime Read:", request)
        else:
            for response in self.client_stub.Read(request):
                yield response

    def ReadRegisters(self, register_id=None, index=None, dry_run=False):
        request = p4runtime_pb2.ReadRequest()
        request.device_id = self.device_id
        entity = request.entities.add()
        register_entry = entity.register_entry
        if register_id is not None:
            register_entry.register_id = register_id
        else:
            register_entry.register_id = 0
        if index is not None:
            register_entry.index.index = index
        if dry_run:
            print( "P4Runtime Read:", request)
        else:
            for response in self.client_stub.Read(request):
                yield response

class GrpcRequestLogger(grpc.UnaryUnaryClientInterceptor,
                        grpc.UnaryStreamClientInterceptor):
    """Implementation of a gRPC interceptor that logs request to a file"""

    def __init__(self, log_file):
        self.log_file = log_file
        with open(self.log_file, 'w') as f:
            # Clear content if it exists.
            f.write("")

    def log_message(self, method_name, body):
        with open(self.log_file, 'a') as f:
            ts = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
            msg = str(body)
            f.write("\n[%s] %s\n---\n" % (ts, method_name))
            if len(msg) < MSG_LOG_MAX_LEN:
                f.write(str(body))
            else:
                f.write("Message too long (%d bytes)! Skipping log...\n" % len(msg))
            f.write('---\n')

    def intercept_unary_unary(self, continuation, client_call_details, request):
        self.log_message(client_call_details.method, request)
        return continuation(client_call_details, request)

    def intercept_unary_stream(self, continuation, client_call_details, request):
        self.log_message(client_call_details.method, request)
        return continuation(client_call_details, request)

class IterableQueue(Queue):
    _sentinel = object()

    def __iter__(self):
        return iter(self.get, self._sentinel)

    def close(self):
        self.put(self._sentinel)
