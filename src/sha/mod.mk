#
# mod.mk
#

ifeq ($(USE_OPENSSL),)
SRCS	+= sha/sha1.c
endif
