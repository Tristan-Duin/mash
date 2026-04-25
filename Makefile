# mash - Masked Shell
#
# POSIX build. Tested on Linux, macOS, WSL, Cygwin, MSYS2.
# Native Windows is not supported - use WSL.
#
# Common targets:
#   make           build ./mash
#   make check     run mask-engine self-tests
#   make install   install to $(PREFIX)/bin (default /usr/local)
#   make clean     remove build artifacts
#
# Variables worth overriding:
#   CC, CFLAGS, LDFLAGS, LDLIBS, PREFIX, DESTDIR
#   V=1            verbose (show full command lines)

# ---- Toolchain & flags -----------------------------------------------------

CC       ?= cc
CSTD     ?= -std=c11
OPT      ?= -O2
WARN     ?= -Wall -Wextra -Wshadow -Wformat=2 -Wpointer-arith \
            -Wstrict-prototypes -Wmissing-prototypes -Wno-unused-parameter
DEFS     ?= -D_GNU_SOURCE -D_POSIX_C_SOURCE=200809L
INCLUDES := -Iinclude
DEPFLAGS := -MMD -MP

CFLAGS   ?= $(CSTD) $(OPT) $(WARN) $(DEFS)
LDFLAGS  ?=
LDLIBS   ?= -lpthread

# openpty(3) lives in libutil on glibc/Linux. macOS, FreeBSD, Cygwin, and
# MSYS2 all expose it from libc, so only Linux needs the extra link line.
UNAME_S  := $(shell uname -s 2>/dev/null)
ifeq ($(UNAME_S),Linux)
LDLIBS   += -lutil
endif

# ---- Layout ----------------------------------------------------------------

SRC_DIR  := src
OBJ_DIR  := build
BIN      := mash

SOURCES  := $(wildcard $(SRC_DIR)/*.c)
OBJECTS  := $(patsubst $(SRC_DIR)/%.c,$(OBJ_DIR)/%.o,$(SOURCES))
DEPS     := $(OBJECTS:.o=.d)

TEST_BIN := tests/test_mask
TEST_SRC := tests/test_mask.c $(SRC_DIR)/mask.c $(SRC_DIR)/util.c

PREFIX   ?= /usr/local
DESTDIR  ?=

# ---- Output control (V=1 for verbose) --------------------------------------

V ?= 0
ifeq ($(V),0)
Q := @
say = @printf '  %-6s %s\n' '$(1)' '$(2)'
else
Q :=
say = @:
endif

# ---- Rules -----------------------------------------------------------------

.PHONY: all check clean install uninstall help
.DEFAULT_GOAL := all

all: $(BIN)

$(BIN): $(OBJECTS)
	$(call say,LINK,$@)
	$(Q)$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c | $(OBJ_DIR)
	$(call say,CC,$<)
	$(Q)$(CC) $(CFLAGS) $(INCLUDES) $(DEPFLAGS) -c -o $@ $<

$(OBJ_DIR):
	$(Q)mkdir -p $@

check: $(TEST_BIN)
	$(call say,RUN,$<)
	$(Q)./$(TEST_BIN)

$(TEST_BIN): $(TEST_SRC) $(wildcard include/*.h)
	$(call say,CC,$@)
	$(Q)$(CC) $(CFLAGS) $(INCLUDES) -o $@ $(TEST_SRC) $(LDLIBS)

clean:
	$(call say,CLEAN,.)
	$(Q)rm -rf $(OBJ_DIR) $(BIN) $(TEST_BIN)

install: $(BIN)
	$(call say,INSTALL,$(DESTDIR)$(PREFIX)/bin/$(BIN))
	$(Q)install -d $(DESTDIR)$(PREFIX)/bin
	$(Q)install -m 0755 $(BIN) $(DESTDIR)$(PREFIX)/bin/$(BIN)

uninstall:
	$(call say,RM,$(DESTDIR)$(PREFIX)/bin/$(BIN))
	$(Q)rm -f $(DESTDIR)$(PREFIX)/bin/$(BIN)

help:
	@echo 'Targets:'
	@echo '  all (default)  Build ./$(BIN)'
	@echo '  check          Build and run mask engine self-tests'
	@echo '  install        Install $(BIN) to $$(DESTDIR)$$(PREFIX)/bin'
	@echo '  uninstall      Remove installed binary'
	@echo '  clean          Remove build artifacts'
	@echo 'Variables:'
	@echo '  PREFIX  = $(PREFIX)'
	@echo '  DESTDIR = $(DESTDIR)'
	@echo '  V=1     verbose command output'

# Auto-track header dependencies.
-include $(DEPS)
