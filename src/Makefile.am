COMMIT=`git describe --dirty --always --tags 2> /dev/null || true`
AM_CFLAGS = -Wall -Werror -DVERSIONCOMMIT=\""$(VERSION), commit: $(COMMIT)"\"
bin_PROGRAMS=hyperstart
hyperstart_SOURCES=init.c jsmn.c net.c util.c parse.c parson.c container.c exec.c event.c portmapping.c netlink.c
if HAVE_VSOCK
hyperstart_SOURCES+=vsock.c
endif
