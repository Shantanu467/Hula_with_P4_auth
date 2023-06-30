import json
import re
import google.protobuf.text_format
from p4.v1 import p4runtime_pb2
from p4.config.v1 import p4info_pb2

p4info = p4info_pb2.P4Info()
# Load the p4info file into a skeleton P4Info object
with open("./build/switch1.p4info") as p4info_f:
    google.protobuf.text_format.Merge(p4info_f.read(), p4info)

registers = {}
for t in p4info.registers:
    pre = t.preamble
    registers[pre.name.split(".")[-1]] = pre.id
    # print(pre.name, " - ",pre.id)
print(registers)
c = len(registers)

def func(output):
    # output.write("a")
    for name in registers:
        if "keys" in name:
            id = registers[name]
            # name = name.split(".")[-1]
            print(name, id)
            action1 = "action "+name+"_read (){\n bit<32>result;\n"+name+".read(result, hdr.packet_out.index);\n}\n"
            output.write(action1)
            action2 = "action "+name+"_write (){\n"+name+".write(hdr.packet_out.index, hdr.packet_out.value);\nsend_packet_in(hdr.packet_out.id, hdr.packet_out.w, hdr.packet_out.index, hdr.packet_out.value);\n}\n"
            output.write(action2)
    table = "table register_map{\nkey = {\n hdr.packet_out.id: exact;\n hdr.packet_out.w: exact;\n}\n"
    table += "actions = {\n drop();\n"
    for name in registers:
        if "keys" in name:
            table += name + "_read();\n"
            table += name + "_write();\n"
    table += "}\n default_action = drop();\n"
    output.write(table)
    entries="const entries = {\n"
    for name in registers:
        print(registers[name])
        if "keys" in name:
            entries+="("+str(hex(registers[name]))+", 0x00) : "+name+"_read ();\n"
            entries+="("+str(hex(registers[name]))+", 0x01) : "+name+"_write ();\n"
    entries+="}\n}\n"
    output.write(entries)



flag = 0
flag_ta = 0
with open("switch1.p4", "r") as inp, open("out.p4", "w") as output:
    for line in inp:
        if "register<" in line:
            flag = 1
        if "apply" in line and ".apply" not in line and flag:
            flag = 0
            func(output)
            flag_ta = 1
        if flag_ta and "{" in line:
            flag_ta = 0
            ind = line.index('{')
            output.write(line[:ind+1])
            tab_apply = "\nif (standard_metadata.ingress_port == CPU_PORT) {\n register_map.apply();\n}\n"
            output.write(tab_apply)
            output.write(line[ind+1:])
        else:
            output.write(line)
