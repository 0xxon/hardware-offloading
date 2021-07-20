
LANGUAGES=cpp
DEFAULT_LANGUAGE=cpp
LANGUAGE_GEN_DIRS=$(foreach x,$(LANGUAGES),$(x)/gen-$(x))

USER_CONFIG=../nic/user_config.json

SCREEN_SESSION=controller

build: $(LANGUAGES)

# Code to allow 3 attempts
install: $(DEFAULT_LANGUAGE)
	sudo screen -d -m -S $(SCREEN_SESSION) bash -c "./$^/controller $(USER_CONFIG) > controller.log 2>&1"

# This command can fail but it should not make the Makefile execution fail too
stop:
	if sudo screen -X -S $(SCREEN_SESSION) quit; then \
		:; \
	fi

.SECONDEXPANSION:
$(LANGUAGES): %: $$@/gen-$$@
	$(MAKE) -C $@

$(LANGUAGE_GEN_DIRS): %: sdk6_rte.thrift
	thrift -r -o $(@D) --gen $(@D) sdk6_rte.thrift;

clean:
	for lang in $(LANGUAGES); do \
		$(MAKE) -w -C $$lang clean; \
	done

.PHONY: build $(LANGUAGES) clean install stop

