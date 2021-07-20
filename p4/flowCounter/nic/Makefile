
SDK_DIR = /opt/netronome/
PROJ = flowCounter

MAIN_P4 = $(PROJ).p4
P4_FILES = $(MAIN_P4)
CONFIG_JSON = user_config.json

NFFW = $(PROJ).nffw
BUILD_DIR = out/

BUILD_OPT = --nfirc_all_header_ops # Allow to modify headers in C
BUILD_OPT += -r # Reduce threads usage (4 instead of 8)
BUILD_OPT += -l hydrogen

$(NFFW): $(P4_FILES) $(SDK_DIR)/p4/bin/nfp4build
	$(SDK_DIR)/p4/bin/nfp4build $(BUILD_OPT) -p $(BUILD_DIR) -o $@ -4 $(P4_FILES)

clean:
	rm -fr $(BUILD_DIR)
	rm -fr *.list
	rm -f $(PROJ).yml
	rm -f Makefile-nfp4build
	rm -f $(NFFW)

design-load: $(BUILD_DIR)/pif_design.json $(NFFW) $(SDK_DIR)/p4/bin/rtecli
	@echo "This operation takes time"
	$(SDK_DIR)/p4/bin/rtecli design-load -p $< -f $(NFFW)

config-reload: $(CONFIG_JSON)
	$(SDK_DIR)/p4/bin/rtecli config-reload -c $<

design-unload: $(SDK_DIR)/p4/bin/rtecli
	@echo "This operation takes time"
	$(SDK_DIR)/p4/bin/rtecli design-unload

.PHONY: clean design-load config-reload design-unload

