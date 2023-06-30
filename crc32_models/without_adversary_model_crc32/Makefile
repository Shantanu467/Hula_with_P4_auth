BMV2_SWITCH_EXE = simple_switch_grpc
TOPO = topology.json
DEFAULT_PROG = switch1.p4
NO_P4 = true
BUILD_DIR = build
PCAP_DIR = pcaps
LOG_DIR = logs

EXTERN_DIR = siphash_extern
EXTERN_LIB = $(EXTERN_DIR)/definition.so

P4C = p4c-bm2-ss
P4C_ARGS += --p4runtime-files $(BUILD_DIR)/$(basename $@).p4.p4info.txt --emit-externs

RUN_SCRIPT = utils/run_exercise.py

ifndef TOPO
TOPO = topology.json
endif

source = $(wildcard *.p4)
compiled_json := $(source:.p4=.json)

ifndef DEFAULT_PROG
DEFAULT_PROG = $(wildcard *.p4)
endif
DEFAULT_JSON = $(BUILD_DIR)/$(DEFAULT_PROG:.p4=.json)

# Define NO_P4 to start BMv2 without a program
ifndef NO_P4
run_args += -j $(DEFAULT_JSON)
endif

# Set BMV2_SWITCH_EXE to override the BMv2 target
ifdef BMV2_SWITCH_EXE
run_args += -b $(BMV2_SWITCH_EXE)
endif

# p4c-bm2-ss --p4v 16 \
# -o test.json \
# --p4runtime-file test.p4info \
# --p4runtime-format text \
# test.p4

all: run

run: build
	sudo python3 $(RUN_SCRIPT) -t $(TOPO) $(run_args)

stop:
	sudo mn -c

build: dirs compile_ $(compiled_json)

compile_:
	$(P4C) --p4v 16 --p4runtime-files build/switch1.p4.p4info.txt -o build/switch1.json switch1.p4 --emit-externs
#	$(P4C) --p4v 16 --p4runtime-files build/switch6.p4.p4info.txt -o build/switch6.json switch6.p4
	$(P4C) --p4v 16 --p4runtime-file build/switch1.p4info --p4runtime-format text switch1.p4 --emit-externs
#	$(P4C) --p4v 16 --p4runtime-file build/switch6.p4info --p4runtime-format text switch6.p4

%.json: %.p4
	$(P4C) --p4v 16 $(P4C_ARGS) -o $(BUILD_DIR)/$@ $<

dirs:
	mkdir -p $(BUILD_DIR) $(PCAP_DIR) $(LOG_DIR)

clean: stop
	rm -f *.pcap
	rm -rf $(BUILD_DIR) $(PCAP_DIR) $(LOG_DIR)
