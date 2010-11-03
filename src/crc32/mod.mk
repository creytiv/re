#
# mod.mk
#

ifeq ($(USE_ZLIB),)
SRCS	+= crc32/crc32.c
endif
