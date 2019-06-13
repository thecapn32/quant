INCLUDE_DIRS+=$(SOURCE_PATH)
CPPSRC+=main.cpp

DEPS=deps
KLIB=$(DEPS)/klib
PICOQUIC=$(DEPS)/picoquic
PICOTLS=$(DEPS)/picotls
WARPCORE=$(DEPS)/warpcore/lib

INCLUDE_DIRS+=\
	$(SOURCE_PATH)/$(WARPCORE)/include \
	$(SOURCE_PATH)/$(WARPCORE)/deps/klib

CSRC+=\
	warpcore/config.c \
	$(WARPCORE)/src/backend_sock.c \
	$(WARPCORE)/src/plat.c \
	$(WARPCORE)/src/util.c \
	$(WARPCORE)/src/warpcore.c

EXTRA_CFLAGS+=-Wno-unknown-pragmas -Werror

# TODO: figure out how to do this using make rules
WARPCORE_VERSION:=$(shell grep 'warpcore.*VERSION' $(SOURCE_PATH)/../../lib/$(WARPCORE)/../CMakeLists.txt | cut -d' ' -f3)
$(shell	cd $(SOURCE_PATH) && ln -sf ../../lib/deps)
$(shell	mkdir -p $(SOURCE_PATH)/warpcore)
$(shell [ -s $(SOURCE_PATH)/warpcore/config.c ] || sed -E -e 's|@PROJECT_NAME@|warpcore|g; s|@PROJECT_NAME_UC@|WARPCORE|g; s|@PROJECT_VERSION@|$(WARPCORE_VERSION)|g; s|(#cmakedefine)|// \1|g' $(SOURCE_PATH)/../../lib/$(WARPCORE)/src/config.c.in > $(SOURCE_PATH)/warpcore/config.c)
$(shell [ -s $(SOURCE_PATH)/warpcore/config.h ] || sed -E -e 's|@PROJECT_NAME@|warpcore|g; s|@PROJECT_NAME_UC@|WARPCORE|g; s|@PROJECT_VERSION@|$(WARPCORE_VERSION)|g; s|(#cmakedefine)|// \1|g' $(SOURCE_PATH)/../../lib/$(WARPCORE)/include/warpcore/config.h.in > $(SOURCE_PATH)/warpcore/config.h)
