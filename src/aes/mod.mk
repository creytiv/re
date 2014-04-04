#
# mod.mk
#
# Copyright (C) 2010 Creytiv.com
#

ifneq ($(USE_OPENSSL),)
SRCS	+= aes/openssl/aes.c
else
SRCS	+= aes/stub.c
endif
