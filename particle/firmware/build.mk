INCLUDE_DIRS+=$(SOURCE_PATH)
CPPSRC+=main.cpp

DEPS=lib/deps
LIBEV=$(DEPS)/libev
KLIB=$(DEPS)/klib
KLIB=$(DEPS)/klib
PICOTLS=$(DEPS)/picotls
WARPCORE=$(DEPS)/warpcore/lib

INCLUDE_DIRS+=\
	$(SOURCE_PATH)/lib/include \
	$(SOURCE_PATH)/$(LIBEV) \
	$(SOURCE_PATH)/$(PICOTLS)/include \
	$(SOURCE_PATH)/$(WARPCORE)/include \
	$(SOURCE_PATH)/$(WARPCORE)/deps/klib

WARP_SRC+=\
	warpcore/config.c \
	$(WARPCORE)/src/backend_sock.c \
	$(WARPCORE)/src/plat.c \
	$(WARPCORE)/src/util.c \
	$(WARPCORE)/src/warpcore.c

QUANT_SRC+=\
	quant/config.c \
	lib/src/quic.c


CSRC+=$(WARP_SRC) $(QUANT_SRC)

EXTRA_CFLAGS+=-Wno-unknown-pragmas -Werror -DNO_FUZZER_CORPUS_COLLECTION

# TODO: figure out how to do this using make rules
$(shell	cd $(SOURCE_PATH) && ln -sf ../../lib)

QUANT_VERSION:=$(shell grep 'warpcore.*VERSION' $(SOURCE_PATH)/../../$(WARPCORE)/CMakeLists.txt | cut -d' ' -f3)
$(shell	mkdir -p $(SOURCE_PATH)/warpcore)
$(shell [ -s $(SOURCE_PATH)/warpcore/config.c ] || \
	sed -E -e 's|@PROJECT_NAME@|warpcore|g; s|@PROJECT_NAME_UC@|WARPCORE|g; s|@PROJECT_VERSION@|$(WARPCORE_VERSION)|g;' \
		$(SOURCE_PATH)/../../$(WARPCORE)/src/config.c.in > $(SOURCE_PATH)/warpcore/config.c)
$(shell [ -s $(SOURCE_PATH)/warpcore/config.h ] || \
	sed -E -e 's|@PROJECT_NAME@|warpcore|g; s|@PROJECT_NAME_UC@|WARPCORE|g; s|@PROJECT_VERSION@|$(WARPCORE_VERSION)|g; s|(#cmakedefine)|// \1|g; s|(@.*@)|0|g;' \
		$(SOURCE_PATH)/../../$(WARPCORE)/include/warpcore/config.h.in > $(SOURCE_PATH)/warpcore/config.h)

QUANT_VERSION:=$(shell grep 'quant.*VERSION' $(SOURCE_PATH)/../../CMakeLists.txt | cut -d' ' -f3)
DRAFT_VERSION:=$(shell grep 'quant.*VERSION' $(SOURCE_PATH)/../../CMakeLists.txt | cut -d' ' -f3 | cut -d. -f3)
$(shell	mkdir -p $(SOURCE_PATH)/quant)
$(shell [ -s $(SOURCE_PATH)/../lib/src/config.c ] || \
	sed -E -e 's|@PROJECT_NAME@|quant|g; s|@PROJECT_NAME_UC@|QUANT|g; s|@PROJECT_VERSION@|$(QUANT_VERSION)|g; s|@PROJECT_VERSION_PATCH@|$(DRAFT_VERSION)|g; s|(@.*@)|0|g;' \
		$(SOURCE_PATH)/../../lib/src/config.c.in > $(SOURCE_PATH)/quant/config.c)
$(shell [ -s $(SOURCE_PATH)/../lib/include/quant/config.h ] || \
	sed -E -e 's|@PROJECT_NAME@|quant|g; s|@PROJECT_NAME_UC@|QUANT|g; s|@PROJECT_VERSION@|$(QUANT_VERSION)|g; s|@PROJECT_VERSION_PATCH@|$(DRAFT_VERSION)|g; s|(#cmakedefine)|// \1|g; s|(@.*@)|0|g;' \
		$(SOURCE_PATH)/../../lib/include/quant/config.h.in > $(SOURCE_PATH)/quant/config.h)
