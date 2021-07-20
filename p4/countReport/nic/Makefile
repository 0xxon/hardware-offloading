
SDK_DIR=/opt/netronome/

PROJ=countReport
MAIN_P4=$(PROJ).p4
P4_FILES=$(MAIN_P4)
C_FILES=primitive_actions.c
CONFIG_JSON=user_config.json
INCLUDE_FOLDER_P4=include/
INCLUDE_FOLDER_C=include_c/

NFFW=$(PROJ).nffw
BUILD_DIR=out/

BUILD_OPT = --nfirc_all_header_ops # Allow to modify headers in C
BUILD_OPT += -e -r # Reduce threads usage (4 instead of 8)
BUILD_OPT += -l hydrogen

CONTROLLER=../controller/cpp/controller

SYSTEMD_CONFIG_FILE=/lib/systemd/system/nfp-sdk6-rte.service
MAX_VFS_TMP=$(shell cat $(SYSTEMD_CONFIG_FILE) | grep "NUM_VFS" | sed -e 's/^Environment=NUM_VFS=//' | tr -d '\n')
# Reserves some channels for controller<->NIC communication
MAX_VFS=$(shell expr $(MAX_VFS_TMP) - 2)

$(NFFW): $(P4_FILES) $(C_FILES) $(SDK_DIR)/p4/bin/nfp4build $(SYSTEMD_CONFIG_FILE)
	$(SDK_DIR)/p4/bin/nfp4build $(BUILD_OPT) -p $(BUILD_DIR) -o $@ -4 $(P4_FILES) -c $(C_FILES) -I $(INCLUDE_FOLDER_C) --nfp4c_I $(INCLUDE_FOLDER_P4) --nfp4c_D "'MAX_VFS=$(MAX_VFS)'" --nfirc_graphs

clean:
	rm -fr $(BUILD_DIR)
	rm -fr *.list
	rm -f $(PROJ).yml
	rm -f Makefile-nfp4build
	rm -f $(NFFW)

install: design-load

stop:

design-load: $(BUILD_DIR)/pif_design.json $(NFFW) $(SDK_DIR)/p4/bin/rtecli
	@echo "This operation takes time"
	$(SDK_DIR)/p4/bin/rtecli design-load -p $< -f $(NFFW)

config-reload: $(CONFIG_JSON) $(CONTROLLER)
	$(CONTROLLER) $<

design-unload: $(SDK_DIR)/p4/bin/rtecli
	@echo "This operation takes time"
	$(SDK_DIR)/p4/bin/rtecli design-unload

.PHONY: clean design-load config-reload design-unload install stop

