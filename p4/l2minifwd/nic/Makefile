
SDK_DIR=/opt/netronome/

PROJ=l2minifwd
MAIN_P4=$(PROJ).p4
P4_FILES=$(MAIN_P4)
CONFIG_JSON=user_config.json

NFFW=$(PROJ).nffw
BUILD_DIR=out/

BUILD_OPT = -l hydrogen

$(NFFW): $(P4_FILES) $(C_FILES) $(SDK_DIR)/p4/bin/nfp4build $(SYSTEMD_CONFIG_FILE)
	$(SDK_DIR)/p4/bin/nfp4build $(BUILD_OPT) -p $(BUILD_DIR) -o $@ -4 $(P4_FILES) --nfirc_graphs

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

test:
	cd ../$@ && sudo python run_tests.py

.PHONY: clean design-load config-reload design-unload test

