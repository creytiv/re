#
# mod.mk
#
# Copyright (C) 2010 Creytiv.com
#

ifneq ($(USE_OPENSSL),)
SRCS	+= tls/openssl/tls.c
SRCS	+= tls/openssl/tls_tcp.c
SRCS	+= tls/openssl/tls_udp.c

USE_OPENSSL_DTLS := $(shell [ -f $(SYSROOT)/include/openssl/dtls1.h ] || \
	[ -f $(SYSROOT)/local/include/openssl/dtls1.h ] || \
	[ -f $(SYSROOT_ALT)/include/openssl/dtls1.h ] && echo "yes")

USE_OPENSSL_SRTP := $(shell [ -f $(SYSROOT)/include/openssl/srtp.h ] || \
	[ -f $(SYSROOT)/local/include/openssl/srtp.h ] || \
	[ -f $(SYSROOT_ALT)/include/openssl/srtp.h ] && echo "yes")

ifneq ($(USE_OPENSSL_DTLS),)
CFLAGS  += -DUSE_OPENSSL_DTLS=1
endif

ifneq ($(USE_OPENSSL_SRTP),)
CFLAGS  += -DUSE_OPENSSL_SRTP=1
endif

endif
