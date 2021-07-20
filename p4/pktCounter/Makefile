
SERVER = nfp-sdk6-rte

SUBDIRS = nic
build: $(SUBDIRS)

$(SUBDIRS):
	$(MAKE) -w -C $@

clean:
	$(MAKE) -w -C nic clean

start_server:
	systemctl start $(SERVER)

server_logs:
	cat /var/log/$(SERVER).log

NIC_PHONY = design-load config-reload design-unload
$(NIC_PHONY):
	if systemctl --quiet is-active $(SERVER); then \
		$(MAKE) -w -C nic $@ ; \
	else \
		echo "Run 'make start_server' before this command"; \
	fi

.PHONY: build $(SUBDIRS) clean start_server server_logs $(NIC_PHONY)

