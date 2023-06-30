import time
import os

runner_ = "python3 ./test-scripts/receive.py --show-probes > ./test-scripts/packet_counts.txt"
os.system(runner_)

counter = "cat ./test-scripts/packet_counts.txt | grep load > ./test-scripts/packet_counts.txt"
os.system(counter)
