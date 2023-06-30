#!/bin/bash 
mkdir build pcaps logs
p4c-bm2-ss --p4v 16 --p4runtime-file build/switch1.p4info --p4runtime-format text -o build/switch1.json switch1.p4
p4c-bm2-ss --p4v 16 --p4runtime-file build/switch2.p4info --p4runtime-format text -o build/switch2.json switch2.p4
sudo python3 utils/run_exercise.py -t topology.json -j build/switch1.json -b simple_switch_grpc