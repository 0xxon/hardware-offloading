
SERVER :=nfp-sdk6-rte

SUBDIRS :=nic controller
DEPLOY_SUBDIRS :=$(addprefix install/,$(SUBDIRS))
DEPLOY_NIC :=install/nic
STOP_SUBDIRS :=$(addprefix stop/,$(SUBDIRS))

build: $(SUBDIRS)

$(SUBDIRS):
	$(MAKE) -w -C $@

# Must be sequential for consistency purposes
full-install:
	$(MAKE) -w $(DEPLOY_NIC)
	$(MAKE) -w install

# Must be sequential for consistency purposes
install:
	for deploy in $(filter-out $(DEPLOY_NIC),$(DEPLOY_SUBDIRS)); do \
		$(MAKE) -w "$${deploy}"; \
		echo "$${deploy}"; \
	done

$(DEPLOY_SUBDIRS): install/%:
	if ! systemctl --quiet is-active $(SERVER); then \
		$(MAKE) start_server; \
	fi
	$(MAKE) -w -C $(@F) install

# Must be sequential for consistency purposes
stop:
	for deploy in $(STOP_SUBDIRS); do \
		$(MAKE) -w "$${deploy}"; \
		echo "$${deploy}"; \
	done

$(STOP_SUBDIRS): stop/%:
	if ! systemctl --quiet is-active $(SERVER); then \
		$(MAKE) start_server; \
	fi
	$(MAKE) -w -C $(@F) stop

clean:
	$(MAKE) -w -C nic clean
	$(MAKE) -w -C controller clean

start_server:
	systemctl start $(SERVER)

server_logs:
	cat /var/log/$(SERVER).log

NIC_PHONY = design-load design-unload
$(NIC_PHONY):
	if systemctl --quiet is-active $(SERVER); then \
		$(MAKE) -w -C nic $@ ; \
	else \
		echo "Run 'make start_server' before this command"; \
	fi

.PHONY: build $(SUBDIRS) clean start_server server_logs $(NIC_PHONY) $(DEPLOY_SUBDIRS) install full-install

