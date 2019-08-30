INCLUDE_DIRS+=$(SOURCE_PATH)
CPPSRC+=main.cpp

DEPS=lib/deps
PICOTLS=$(DEPS)/picotls
TIMEOUT=$(DEPS)/timeout
WARPCORE=$(DEPS)/warpcore/lib

INCLUDE_DIRS+=\
	$(SOURCE_PATH)/$(PICOTLS)/deps/cifra/src \
	$(SOURCE_PATH)/$(PICOTLS)/deps/cifra/src/ext \
	$(SOURCE_PATH)/$(PICOTLS)/deps/micro-ecc \
	$(SOURCE_PATH)/$(PICOTLS)/include \
	$(SOURCE_PATH)/$(TIMEOUT) \
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
	$(PICOTLS)/deps/cifra/src/sha512.c \
	$(PICOTLS)/deps/micro-ecc/uECC.c \
	$(PICOTLS)/lib/cifra/aes128.c \
	$(PICOTLS)/lib/picotls.c \
	$(PICOTLS)/lib/uecc.c

TIMEOUT_SRC+=\
	$(TIMEOUT)/timeout.c

WARP_SRC+=\
	$(WARPCORE)/src/backend_sock.c \
	$(WARPCORE)/src/plat.c \
	$(WARPCORE)/src/util.c \
	$(WARPCORE)/src/warpcore.c \
	warpcore/config.c

QUANT_SRC+=\
	lib/src/conn.c \
	lib/src/diet.c \
	lib/src/frame.c \
	lib/src/loop.c \
	lib/src/marshall.c \
	lib/src/pkt.c \
	lib/src/pn.c \
	lib/src/quic.c \
	lib/src/recovery.c \
	lib/src/stream.c \
	lib/src/tls.c \
	quant/config.c


CSRC+=$(WARP_SRC) $(PICOTLS_SRC) $(TIMEOUT_SRC) $(QUANT_SRC)

EXTRA_CFLAGS+= \
	-foptimize-strlen -ffast-math \
	-Wno-error -Wno-parentheses -Wno-undef -Wno-unknown-pragmas \
	-Wno-unused-value -Wno-address \
	-DDLEVEL=DBG -DNDEBUG -DNDEBUG_WITH_DLOG -DTIMEOUT_DISABLE_INTERVALS \
	-DNO_FUZZER_CORPUS_COLLECTION -DNO_TLS_TICKETS -DNO_TLS_LOG -DNO_QLOG \
	-DNO_ERR_REASONS -DNO_OOO_0RTT -DNO_OOO_DATA -DNO_MIGRATION \
	-D'ntoh16(x)=__builtin_bswap16(*(uint16_t*)(x))' \
	-D'ntoh24(x)=__builtin_bswap16(*(uint16_t*)(x)) << 8 | (x)[2]' \
	-D'ntoh32(x)=__builtin_bswap32(*(uint32_t*)(x))' \
	-D'ntoh64(x)=__builtin_bswap64(*(uint64_t*)(x))'

# TODO: figure out how to do this using make rules
$(shell	cd $(SOURCE_PATH) && ln -sf ../../lib)

WARPCORE_VERSION:=$(shell grep 'warpcore.*VERSION' $(SOURCE_PATH)/../../$(WARPCORE)/../CMakeLists.txt | cut -d' ' -f3)
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
