CC      ?= gcc
CLANG   ?= clang
CFLAGS  := -O3 -march=native -Wall -Wextra
MOD_DIR := modules
BUILD   := /tmp/zero_build

MOD_SOS := $(BUILD)/libmod_deception_tarpit.so \
           $(BUILD)/libmod_xdp_guardian.so \
           $(BUILD)/libmod_entropy_shaper.so \
           $(BUILD)/libmod_http_guard.so \
           $(BUILD)/libmod_anti_spoof.so \
           $(BUILD)/libmod_ai_wd.so \
           $(BUILD)/libmod_https_tls.so \
           $(BUILD)/libmod_egress.so \
           $(BUILD)/libmod_rmm_asm.so

.PHONY: all modules recorder test clean

all: modules recorder

$(BUILD):
	mkdir -p $(BUILD)

modules: $(BUILD) $(MOD_SOS) $(BUILD)/chain_orchestrator

$(BUILD)/libmod_deception_tarpit.so: $(MOD_DIR)/deception_tarpit/deception_tarpit.c
	$(CC) $(CFLAGS) -shared -fPIC $< -o $@

$(BUILD)/libmod_xdp_guardian.so: $(MOD_DIR)/xdp_live_daemon/xdp_live_daemon.c
	$(CC) $(CFLAGS) -shared -fPIC $< -o $@

$(BUILD)/libmod_entropy_shaper.so: $(MOD_DIR)/entropy_shaper/entropy_shaper.c
	$(CC) $(CFLAGS) -shared -fPIC $< -o $@

$(BUILD)/libmod_http_guard.so: $(MOD_DIR)/http_table_guard/http_table_guard.c
	$(CC) $(CFLAGS) -shared -fPIC $< -o $@

$(BUILD)/libmod_anti_spoof.so: $(MOD_DIR)/anti_spoof_guard/anti_spoof_guard.c
	$(CC) $(CFLAGS) -shared -fPIC $< -o $@

$(BUILD)/libmod_ai_wd.so: $(MOD_DIR)/ai_agent_watchdog/ai_watchdog.c
	$(CC) $(CFLAGS) -shared -fPIC $< -o $@

$(BUILD)/libmod_https_tls.so: $(MOD_DIR)/https_tls_guard/https_tls_guard.c
	$(CC) $(CFLAGS) -shared -fPIC $< -o $@

	$(CC) $(CFLAGS) -shared -fPIC $< -o $@

$(BUILD)/libmod_egress.so: $(MOD_DIR)/egress_wire_mutator/egress_mutator.c
	$(CC) $(CFLAGS) -shared -fPIC $< -o $@

$(BUILD)/libmod_rmm_asm.so: $(MOD_DIR)/rmm_control_guard/rmm_guard.S
	$(CC) -shared -fPIC -nostdlib $< -o $@

$(BUILD)/chain_orchestrator: $(MOD_DIR)/chain_orchestrator.c
	$(CC) $(CFLAGS) -I$(MOD_DIR) $< -ldl -o $@

recorder: $(BUILD) flight_recorder/uring_dumper.c
	$(CC) $(CFLAGS) flight_recorder/uring_dumper.c -o $(BUILD)/uring_dumper

test: modules recorder
	$(BUILD)/uring_dumper

clean:
	rm -rf $(BUILD)
