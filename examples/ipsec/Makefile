ifndef TARGET
${error You MUST set TARGET}
endif

CONTIKI_PROJECT=ipsec-example

UIP_CONF_IPV6=1
CFLAGS += -DPROJECT_CONF_H=\"ipsec-conf.h\" 

CONTIKI = ../..

# For msp430 and stm32l, among others
SMALL=1

# Enable the below includes if you are using the native target
#

# Are we targeting the native (i.e. your PC) platform? If so, enable the native border router.
# Run "make connect-router" in order to set up the IPv6 tunnel
ifeq ($(TARGET),native)
PROJECTDIRS += $(CONTIKI)/examples/ipv6/native-border-router
CONTIKI_SOURCEFILES += border-router-cmds.c tun-bridge.c border-router-rdc.c \
slip-config.c slip-dev.c border-router.c
APPS = slip-cmd
CFLAGS += -DCMD_CONF_OUTPUT=border_router_cmd_output -DUIP_FALLBACK_INTERFACE=rpl_interface -DCONTIKI_TARGET_NATIVE=1
endif

all: $(CONTIKI_PROJECT)

#∫
# HEAP size increase for the IAR compiler. This is a must as both the IPsec and IKEv2 implementation
# depends on malloc(). The heap size is in hex (ex. 0x400 bytes = 1024 bytes). 
#
IAR_DATA16_HEAP_SIZE=1000
IAR_STACK_SIZE=790

include $(CONTIKI)/Makefile.include

connect-router:	$(CONTIKI_PROJECT).native
	sudo ./$(CONTIKI_PROJECT).native -s /dev/null aaaa::1/64



# Favourite arguments
#  valgrind --leak-check=yes  --error-limit=no
# --gen-suppressions=all --log-file=valgrind/minimalraw.log
# --suppressions=valgrind/ipsec.supp
#--gen-suppressions=all --log-file=valgrind/minimalraw.log
# valgrind --leak-check=yes
# gdb -tui --args


#APPS = slip-cmd
# 
# CONTIKI=../..
# TARGET=native
# 
# WITH_UIP6=1
# UIP_CONF_IPV6=1
# CFLAGS+= -DUIP_CONF_IPV6_RPL
# 
# #linker optimizations
# SMALL=1
# 
# CFLAGS += -DPROJECT_CONF_H=\"ipsec-conf.h\"
# 
# WITH_WEBSERVER=1
# ifeq ($(WITH_WEBSERVER),1)
# CFLAGS += -DWEBSERVER=1
# PROJECT_SOURCEFILES += httpd-simple.c
# else ifneq ($(WITH_WEBSERVER), 0)
# APPS += $(WITH_WEBSERVER)
# CFLAGS += -DWEBSERVER=2
# endif
# 
# include $(CONTIKI)/Makefile.include
# 
# connect-router:	$(CONTIKI_PROJECT).native
# 	sudo  ./$(CONTIKI_PROJECT).native -s /dev/null aaaa::1/64

# Favourite arguments
#  valgrind --leak-check=yes  --error-limit=no
# --gen-suppressions=all --log-file=valgrind/minimalraw.log
# --suppressions=valgrind/ipsec.supp
#--gen-suppressions=all --log-file=valgrind/minimalraw.log
# valgrind --leak-check=yes
# gdb -tui --args