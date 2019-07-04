INCLUDE_DIRS+=$(SOURCE_PATH)
CPPSRC+=main.cpp

DEPS=lib/deps
PICOTLS=$(DEPS)/picotls
WARPCORE=$(DEPS)/warpcore/lib

INCLUDE_DIRS+=\
	$(SOURCE_PATH)/$(PICOTLS)/deps/cifra/src \
	$(SOURCE_PATH)/$(PICOTLS)/deps/cifra/src/ext \
	$(SOURCE_PATH)/$(PICOTLS)/deps/micro-ecc \
	$(SOURCE_PATH)/$(PICOTLS)/include \
	$(SOURCE_PATH)/$(WARPCORE)/deps/klib \
	$(SOURCE_PATH)/$(WARPCORE)/include \
	$(SOURCE_PATH)/lib/include

PICOTLS_SRC+=\
	$(PICOTLS)/deps/cifra/src/aes.c \
	$(PICOTLS)/deps/cifra/src/blockwise.c \
	$(PICOTLS)/deps/cifra/src/drbg.c \
	$(PICOTLS)/deps/cifra/src/gcm.c \
	$(PICOTLS)/deps/cifra/src/gf128.c \
	$(PICOTLS)/deps/cifra/src/modes.c \
	$(PICOTLS)/deps/cifra/src/sha256.c \
	$(PICOTLS)/deps/micro-ecc/uECC.c \
	$(PICOTLS)/lib/cifra.c \
	$(PICOTLS)/lib/picotls.c \
	$(PICOTLS)/lib/uecc.c

WARP_SRC+=\
	$(WARPCORE)/src/backend_sock.c \
	$(WARPCORE)/src/plat.c \
	$(WARPCORE)/src/util.c \
	$(WARPCORE)/src/warpcore.c \
	warpcore/config.c

QUANT_SRC+=\
	lib/src/conn.c \
	lib/src/diet.c \
	lib/src/event.c \
	lib/src/frame.c \
	lib/src/marshall.c \
	lib/src/pkt.c \
	lib/src/pn.c \
	lib/src/quic.c \
	lib/src/recovery.c \
	lib/src/stream.c \
	lib/src/tls.c \
	quant/config.c


CSRC+=$(WARP_SRC) $(PICOTLS_SRC) $(QUANT_SRC)

# -DNDEBUG
EXTRA_CFLAGS+=-Wno-error -Wno-parentheses -Wno-unused-function -Wno-comment \
	-Wno-undef -Wno-unknown-pragmas -Wno-unused-but-set-variable \
	-DNO_FUZZER_CORPUS_COLLECTION -DNO_OOO_0RTT -DNO_TLS_TICKETS \
	-DNO_TLS_LOG -DMINIMAL_CIPHERS -DNO_ERR_REASONS -DNDEBUG \
	-DEXTERNAL_READ_ENTROPY -DNO_OOO_DATA \
	-DLOG_COMPILE_TIME_LEVEL=LOG_LEVEL_ALL

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
