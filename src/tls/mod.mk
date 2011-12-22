#
# mod.mk
#
# Copyright (C) 2010 Creytiv.com
#

ifneq ($(USE_OPENSSL),)
SRCS	+= tls/openssl/tls.c
SRCS	+= tls/openssl/tls_tcp.c

USE_OPENSSL_DTLS := $(shell [ -f $(SYSROOT)/include/openssl/dtls1.h ] || \
	[ -f $(SYSROOT)/local/include/openssl/dtls1.h ] || \
	[ -f $(SYSROOT_ALT)/include/openssl/dtls1.h ] && echo "yes")

ifneq ($(USE_OPENSSL_DTLS),)
CFLAGS  += -DUSE_OPENSSL_DTLS=1
SRCS	+= tls/openssl/tls_udp.c
endif

endif
