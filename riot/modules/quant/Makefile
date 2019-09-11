NO_AUTO_SRC = 1

WARP_SRC = lib/deps/warpcore/lib/src
WARP_INC = lib/deps/warpcore/lib/include

SRC += \
	quant/config.c \
	warpcore/config.c \
	$(RIOTPROJECT)/$(WARP_SRC)/backend_riot.c \
	$(RIOTPROJECT)/$(WARP_SRC)/warpcore.c \
	$(RIOTPROJECT)/$(WARP_SRC)/plat.c \
	$(RIOTPROJECT)/$(WARP_SRC)/util.c \
	$(RIOTPROJECT)/test/minimal_transaction.c

.PHONY: dirs

all: quant/config.c warpcore/config.c

INCLUDES += \
	-isystem $(CURDIR) \
	-isystem $(RIOTPROJECT)/$(WARP_INC)

CFLAGS += \
	-Wno-unknown-pragmas \
	-DDLEVEL=DBG

include $(RIOTBASE)/Makefile.base

dirs:
	@# make a bunch of unusual directories for the out-of-tree dependencies
	@mkdir -p quant warpcore \
		$(BINDIR)/$(MODULE)/quant/quant \
		$(BINDIR)/$(MODULE)/warpcore \
		$(BINDIR)/$(MODULE)/$(RIOTPROJECT)/$(WARP_SRC) \
		$(BINDIR)/$(MODULE)/$(RIOTPROJECT)/test

QUANT_VERSION=$(shell grep 'quant.*VERSION' $(RIOTPROJECT)/CMakeLists.txt | cut -d' ' -f3)
DRAFT_VERSION=$(shell grep 'quant.*VERSION' $(RIOTPROJECT)/CMakeLists.txt | cut -d' ' -f3 | cut -d. -f3)

quant/config.c: $(RIOTPROJECT)/lib/src/config.c.in quant/config.h
	@sed -E -e 's|@PROJECT_NAME@|quant|g; s|@PROJECT_NAME_UC@|QUANT|g; s|@PROJECT_VERSION@|$(QUANT_VERSION)|g; s|@PROJECT_VERSION_PATCH@|$(DRAFT_VERSION)|g; s|(@.*@)|0|g;' \
		$< > $@

quant/config.h: $(RIOTPROJECT)/lib/include/quant/config.h.in dirs
	@sed -E -e 's|@PROJECT_NAME@|quant|g; s|@PROJECT_NAME_UC@|QUANT|g; s|@PROJECT_VERSION@|$(QUANT_VERSION)|g; s|@PROJECT_VERSION_PATCH@|$(DRAFT_VERSION)|g; s|(#cmakedefine)|// \1|g; s|(@.*@)|0|g;' \
		$< > $@

WARPCORE_VERSION:=$(shell grep 'warpcore.*VERSION' $(RIOTPROJECT)/lib/deps/warpcore/CMakeLists.txt | cut -d' ' -f3)

warpcore/config.c: $(RIOTPROJECT)/$(WARP_SRC)/config.c.in warpcore/config.h
	@sed -E -e 's|@PROJECT_NAME@|warpcore|g; s|@PROJECT_NAME_UC@|WARPCORE|g; s|@PROJECT_VERSION@|$(WARPCORE_VERSION)|g;' \
		$< > $@

warpcore/config.h: $(RIOTPROJECT)/$(WARP_INC)/warpcore/config.h.in dirs
	@sed -E -e 's|@PROJECT_NAME@|warpcore|g; s|@PROJECT_NAME_UC@|WARPCORE|g; s|@PROJECT_VERSION@|$(WARPCORE_VERSION)|g; s|(#cmakedefine)|// \1|g; s|(@.*@)|0|g;' \
		$< > $@

