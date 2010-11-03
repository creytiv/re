#
# mod.mk
#


SRCS	+= main/init.c
SRCS	+= main/main.c
SRCS	+= main/method.c

ifneq ($(HAVE_EPOLL),)
SRCS	+= main/epoll.c
endif
