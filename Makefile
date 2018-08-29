#
# Makefile
#
# Copyright (C) 2010 Creytiv.com
#

# Master version number
VER_MAJOR := 0
VER_MINOR := 5
VER_PATCH := 9

PROJECT   := re
VERSION   := 0.5.9

MK	:= mk/re.mk

include $(MK)

# List of modules
MODULES += sip sipevent sipreg sipsess
MODULES += uri http httpauth msg websock
MODULES += stun turn ice
MODULES += natbd
MODULES += rtp sdp jbuf telev
MODULES += dns
MODULES += md5 crc32 sha hmac base64
MODULES += udp sa net tcp tls
MODULES += list mbuf hash
MODULES += fmt tmr main mem dbg sys lock mqueue
MODULES += mod conf
MODULES += bfcp
MODULES += aes srtp
MODULES += odict
MODULES += json

INSTALL := install
ifeq ($(DESTDIR),)
PREFIX  ?= /usr/local
else
PREFIX  ?= /usr
endif
ifeq ($(LIBDIR),)
LIBDIR  := $(PREFIX)/lib
endif
INCDIR  := $(PREFIX)/include/re
MKDIR   := $(PREFIX)/share/re
CFLAGS	+= -Iinclude

MODMKS	:= $(patsubst %,src/%/mod.mk,$(MODULES))
SHARED  := $(BUILD)/libre$(LIB_SUFFIX)
STATIC	:= $(BUILD)/libre.a
PKG-CONFIG := $(BUILD)/libre.pc

include $(MODMKS)


OBJS	?= $(patsubst %.c,$(BUILD)/%.o,$(SRCS))


all: $(SHARED) $(STATIC)


-include $(OBJS:.o=.d)


$(SHARED): $(OBJS)
	@echo "  LD      $@"
	@$(LD) $(LFLAGS) $(SH_LFLAGS) $^ $(LIBS) -o $@


$(STATIC): $(OBJS)
	@echo "  AR      $@"
	@$(AR) $(AFLAGS) $@ $^
ifneq ($(RANLIB),)
	@$(RANLIB) $@
endif

$(PKG-CONFIG):
	@echo 'prefix='$(PREFIX) > $(PKG-CONFIG)
	@echo 'exec_prefix=$${prefix}' >> $(PKG-CONFIG)
	@echo 'libdir=$${prefix}/lib' >> $(PKG-CONFIG)
	@echo 'includedir=$${prefix}/include/re' >> $(PKG-CONFIG)
	@echo '' >> $(PKG-CONFIG)
	@echo 'Name: libre' >> $(PKG-CONFIG)
	@echo 'Description: ' >> $(PKG-CONFIG)
	@echo 'Version: '$(VERSION) >> $(PKG-CONFIG)
	@echo 'URL: http://creytiv.com/re.html' >> $(PKG-CONFIG)
	@echo 'Libs: -L$${libdir} -lre' >> $(PKG-CONFIG)
	@echo 'Libs.private: -L$${libdir} -lre ${LIBS}' >> $(PKG-CONFIG)
	@echo 'Cflags: -I$${includedir}' >> $(PKG-CONFIG)

$(BUILD)/%.o: src/%.c $(BUILD) Makefile $(MK) $(MODMKS)
	@echo "  CC      $@"
	@$(CC) $(CFLAGS) -c $< -o $@ $(DFLAGS)


$(BUILD): Makefile $(MK) $(MODMKS)
	@mkdir -p $(patsubst %,$(BUILD)/%,$(sort $(dir $(SRCS))))
	@touch $@


.PHONY: clean
clean:
	@rm -rf $(SHARED) $(STATIC) $(PKG-CONFIG) test.d test.o test $(BUILD)


install: $(SHARED) $(STATIC) $(PKG-CONFIG)
	@mkdir -p $(DESTDIR)$(LIBDIR) $(DESTDIR)$(LIBDIR)/pkgconfig \
		$(DESTDIR)$(INCDIR) $(DESTDIR)$(MKDIR)
	$(INSTALL) -m 0644 $(shell find include -name "*.h") \
		$(DESTDIR)$(INCDIR)
	$(INSTALL) -m 0755 $(SHARED) $(DESTDIR)$(LIBDIR)
	$(INSTALL) -m 0755 $(STATIC) $(DESTDIR)$(LIBDIR)
	$(INSTALL) -m 0644 $(PKG-CONFIG) $(DESTDIR)$(LIBDIR)/pkgconfig
	$(INSTALL) -m 0644 $(MK) $(DESTDIR)$(MKDIR)

uninstall:
	@rm -rf $(DESTDIR)$(INCDIR)
	@rm -rf $(DESTDIR)$(MKDIR)
	@rm -f $(DESTDIR)$(LIBDIR)/$(SHARED)
	@rm -f $(DESTDIR)$(LIBDIR)/$(STATIC)
	@rm -f $(DESTDIR)$(LIBDIR)/pkgconfig/libre.pc

-include test.d

test.o:	test.c Makefile $(MK)
	@echo "  CC      $@"
	@$(CC) $(CFLAGS) -c $< -o $@ $(DFLAGS)

test$(BIN_SUFFIX): test.o $(SHARED) $(STATIC)
	@echo "  LD      $@"
	@$(LD) $(LFLAGS) $< -L. -lre $(LIBS) -o $@

sym:	$(SHARED)
	@nm $(SHARED) | grep " U " | perl -pe 's/\s*U\s+(.*)/$${1}/' \
		> docs/symbols.txt
	@echo "$(SHARED) is using `cat docs/symbols.txt | wc -l ` symbols"
