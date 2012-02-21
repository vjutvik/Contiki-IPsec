CONTIKI_PROJECT=ipsec-example
all: $(CONTIKI_PROJECT)
APPS = slip-cmd

CONTIKI=../..
TARGET=native

WITH_UIP6=1
UIP_CONF_IPV6=1
CFLAGS+= -DUIP_CONF_IPV6_RPL

#linker optimizations
SMALL=1

CFLAGS += -DPROJECT_CONF_H=\"ipsec-conf.h\"
PROJECTDIRS += $(CONTIKI)/examples/ipv6/native-border-router
CONTIKI_SOURCEFILES += border-router-cmds.c tun-bridge.c border-router-rdc.c \
slip-config.c slip-dev.c border-router.c

WITH_WEBSERVER=1
ifeq ($(WITH_WEBSERVER),1)
CFLAGS += -DWEBSERVER=1
PROJECT_SOURCEFILES += httpd-simple.c
else ifneq ($(WITH_WEBSERVER), 0)
APPS += $(WITH_WEBSERVER)
CFLAGS += -DWEBSERVER=2
endif

include $(CONTIKI)/Makefile.include

connect-router:	$(CONTIKI_PROJECT).native
	sudo ./$(CONTIKI_PROJECT).native -s /dev/null aaaa::1/64
