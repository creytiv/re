#
# mod.mk
#

SRCS	+= mqueue/mqueue.c

ifeq ($(OS),win32)
SRCS	+= mqueue/win32/pipe.c
endif
