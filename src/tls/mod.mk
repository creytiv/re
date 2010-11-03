#
# mod.mk
#


ifneq ($(USE_OPENSSL),)
SRCS	+= tls/openssl/tls.c
SRCS	+= tls/openssl/tls_tcp.c
endif
