# Makefile for libsodium VRF implementation

SRCPATH    := $(shell pwd)
OS_TYPE    := $(shell uname | tr '[:upper:]' '[:lower:]')
ARCH       := $(shell uname -m)
LIBSODIUM_DIR := ./libsodium-fork
LIBS_DIR    := $(SRCPATH)/libs/$(OS_TYPE)/$(ARCH)

default: build-libsodium

build-libsodium:
	@echo "Building libsodium for $(OS_TYPE)/$(ARCH) from $(LIBSODIUM_DIR)"
	mkdir -p $(SRCPATH)/copies/$(OS_TYPE)/$(ARCH)
	if [ -d "$(LIBSODIUM_DIR)" ]; then \
		cp -R $(LIBSODIUM_DIR)/. $(SRCPATH)/copies/$(OS_TYPE)/$(ARCH)/libsodium-fork && \
		cd $(SRCPATH)/copies/$(OS_TYPE)/$(ARCH)/libsodium-fork && \
		./autogen.sh --prefix $(LIBS_DIR) && \
		./configure --disable-shared --prefix="$(LIBS_DIR)" $(EXTRA_CONFIGURE_FLAGS) && \
		$(MAKE) && \
		$(MAKE) install && \
		echo "Libsodium build successful"; \
	else \
		echo "Error: Libsodium directory not found at $(LIBSODIUM_DIR)"; \
		exit 1; \
	fi

clean:
	if [ -d "$(LIBSODIUM_DIR)" ]; then \
		cd $(LIBSODIUM_DIR) && \
		test ! -e Makefile || make clean; \
	fi
	rm -rf $(SRCPATH)/lib
	rm -rf $(SRCPATH)/libs
	rm -rf $(SRCPATH)/copies
	rm -rf $(LIBS_DIR)

.PHONY: default build-libsodium clean
