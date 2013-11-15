What is Contiki-IPsec?
======================
Contiki-IPsec is a patch to the popular Internet of Things operating system, Contiki. It's a basic implementation of IPsec, the network layer security extension of IPv6, and a daemon for automatically negotiating secure connections with other hosts - IKEv2.

If you're accustomed to application layer security such as TLS / SSL, you'll find IPsec much different as it'll make security a concern of the operating system, not the application. 


What is IPsec and IKEv2?
========================

IPsec according to Wikipedia:

"IPsec is an end-to-end security scheme operating in the Internet Layer of the Internet Protocol Suite. It can be used in protecting data flows between a pair of hosts (host-to-host), between a pair of security gateways (network-to-network), or between a security gateway and a host (network-to-host).[1]"

The security between the hosts are dependent upon shared secrets which IPsec stores in a structure called Security Associations (SAs). SAs can be manually created by an administrator or automatically by an IKEv2 daemon which negotiates it with the other host.

IPsec and IKEv2 are described in RFC no. 4301 and 5996, respectively.


A typical IKEv2 handshake
-------------------------
An IKEv2 negotiation takes place over port 500 UDP. Page 6 in RFC 5996 describes the exchanges as follows:

> An IKE message flow always consists of a request followed by a response. It is the responsibility of the requester to ensure reliability. If
> the response is not received within a timeout interval, the requester needs to retransmit the request (or abandon the connection).
> 
> The first exchange of an IKE session, IKE\_SA\_INIT, negotiates security parameters for the IKE SA, sends nonces, and sends Diffie-Hellman values.
> 
> The second exchange, IKE\_AUTH, transmits identities, proves knowledge of the secrets corresponding to the two identities, and sets up an SA
> for the first (and often only) AH or ESP Child SA (unless there is failure setting up the AH or ESP Child SA, in which case the IKE SA is 
> still established without the Child SA).
> 
> The types of subsequent exchanges are CREATE\_CHILD\_SA (which creates a Child SA) and INFORMATIONAL (which deletes an SA, reports error
> conditions, or does other housekeeping). Every request requires a response. An INFORMATIONAL request with no payloads (other than the 
> empty Encrypted payload required by the syntax) is commonly used as a check for liveness. These subsequent exchanges cannot be used until
> the initial exchanges have completed.

Implementation Features
=======================

IPsec
-----
Should be nearly standards-compliant in terms of features. 

### Major features implemented ###
* Replay protection
* The IPsec ESP protocol
* Transport mode
* Traffic selectors (traffic multiplexing over SAs)
* SAD, with SA expiration mechanism
* SPD and related functions (incl. one SA offer for each SPD rule)
* Encryption
  * ESP-NULL
  * AES-CTR, varying key length (only 128 bit tested). Partial rewrite of Simon's code.
  * AES-XCBC. Partial rewrite of Simon Duquennoy's code.
* Integrity
  * AES-XCBC. Partial rewrite of Simon Duquennoy's code.

### Major features not implemented ###
* The IPsec AH protocol
* Tunnel mode
* Various integrity and encryption algorithms tagged as REQUIRED


IKEv2
-----
Implements a subset of RFC 5996 and associated standards, but is not standards-compliant because of missing features.

### Major features implemented ###
* State machine for responder
* State machine for initiator
* ECC DH (only DH group 25)
* Authentication by means of pre-shared key
* Traffic selector negotiation (note: this is only a simplification of section 2.9's algorithm)
* SPD interface that allows multiple IKE SA offers
* SK payload: Encryption and integrity is the same as in IPsec (it's a common interface)
* Multiple concurrent sessions supported
* Multiple child SAs per IKE SA
  
### Major features not implemented ###
* Cookie handling (the code is there, but it's not tested)
* Tunnel mode SA negotiation
* EAP
* NAT support
* IPcomp support
* Only IDs of type ID\_RFC822\_ADDR (e-mail address) are supported (trivial to extend though)
* Support for X.509 Certificates as IDs or means of authentication


### Basic features that ought to be implemented in IKEv2 ###
* Deletion of Child and IKE SAs (Delete payload)
* State machine Established can't create child SAs currently (this is a straightforward extension though)
 
Performance / Hardware requirements
===================================
This IPsec patch can be divided into two major components: IPsec base (static keying only) and dynamic keying (IKEv2 service). The system can be configured with both or only the first. Using IPsec base only consumes approximately 8 kB of ROM. Adding dynamic keying on top of that brings the total ROM requirement to approximately 26,5 kB. This includes the library for asymmetric encryption.

Both components have been tested on an emulated (Cooja running MSPsim) Wismote (16 MHz MSP430x CPU) as well as a Linux native process (the native target). In testing, a complete IKEv2 handshake between the emulated Wismote (100% emulation speed) and a Linux PC using a 192 bit ECC key took 10 seconds.

If you are looking for IPsec functionality with the smallest possible memory footprint, you can use Simon Duquennoy's implementation which you will find at https://github.com/tecip-nes/contiki-tres/wiki/Building-the-latest-version-of-mspgcc
It's more limited than this implementation, e.g. you can only use one static key, but it's known to work well.


Quick Demonstration Setup of IPsec and IKEv2
============================================
This section explains how an IPsec demonstration system is built, configured and tested. The setup is composed of a Linux host running Strongswan and a Contiki-node using this IPsec patch. As this patch does not implement tunnel mode the demonstration will establish a host-to-host SA pair. We will then demonstrate the successful transmission and reception of a protected UDP datagram.


Configuring Contiki
-------------------
The IPsec patch follows the Contiki tradition of leaving most of the configuration to preprocessor options. For IPsec this means that the SPD, IKEv2's offers and manual SAs are set at compile time.

### Main Configuration ###
The IPsec patch's main configuration is positioned in examples/ipsec/ipsec-conf.h. All identifiers should have been properly set for this demonstration.

### Configuring the SPD ###
SPD, or Security Policy Database, is the set of rules that dictates what IP-traffic is to be protected by IPsec, and which is not. The implementation closely follows the structure outlined in RFC 4301. The relevant passage begins at p. 19, section 4.4.1.

The declaration of the SPD is made in the array spd\_table located in the file core/net/ipsec/spd\_conf.c, line 127. Whenever an IP-packet is about to enter or leave the system (forwarded packets are not considered though), the array is traversed from the top to the bottom until a rule with a matching traffic pattern is found. The existing table is suited to the example in this README, but *you must substitute the IPv6-addresses used therein with those of your system*. Failure to do so will result in an inoperative system.

More help is available in the source code's comments and section 4.4.1 of RFC 4301.


Building Contiki with IPsec and IKEv2
-------------------------------------
The Contiki system can be built and run on any machine. As IPsec is a part of the IPv6 stack, the only requirement is that they must be able to communicate over IPv6.


### The Wismote (MSP430x) Target ###
The [Wismote](http://wismote.org/) is a suitable test platform for IPsec as it provides ample RAM and FLASH. It can also be emulated in Cooja which makes it even more attractive for experimentation.

Even though Wismote can run MSP430-binaries compiled with GCC, this IPsec patch must be compiled using the MSP430X instruction set (20-bit memory instructions) as the memory space provided by the 16-bit MSP430 is not enough. As of January 2013, support for this target has still not made it to mainline MSPGCC. Therefore the build system is set up for using a compiler from [IAR Systems](http://www.iar.com) that only runs Windows environments.

Therefore, the recommended procedure is to check out this code in MS Windows, and execute the following in a Cygwin environment running on top of it (while in the directory examples/ipsec):
	make TARGET=wismote

(UPDATE: 20 September 2013: Alex Papanikolaou writes to say that as of now, there is a guide for building the msp430-gcc development version (4.7.0) which features 20-bit instruction set support at http://wiki.contiki-os.org/doku.php?id=msp430x Please be warned that you may experience weird/unstable behaviour.)

(UPDATE 2: 15 November 2013: Niclas Finne writes to alert me that _the 4.7.0 version of MSPgcc that is included in the latest Instant Contiki is quite broken_. The author have had much success with 4.7.2 and therefore suggests that you use that instead, preferably by using the following script (supplied by Real-Time Networks research group, Scuola Superiore Sant'Anna): https://github.com/tecip-nes/contiki-tres/wiki/Building-the-latest-version-of-mspgcc))


### The Native Target ###
When Contiki is compiled for the native target the output will be a binary that can be run as an ordinary Linux process. IP connectivity is provided by means of a tunnel.

To begin compilation, execute while in the directory examples/ipsec:

	make TARGET=native

### The u101-stm32l target (not tested) ###
This it the target associated with the new platform from UPWIS. The IPsec patch is known to compile for this target, but it has not been tested on the actual hardware as the port of Contiki had not been completed at the time of testing.

### Building for other targets ###
Please see the section "Porting to other targets"

### Porting to other targets ###
The IPsec patch has only been tested for the native and the Wismote targets, but it can be ported to any target provided it has enough ROM and RAM.

Porting should be straightforward as the IPsec patch doesn't depend on any special-purpose hardware. The only hardware-specific configuration is located in core/lib/contikecc/ecc/Makefile.ecc which needs to reviewed for any porting project.

Setting up Linux
----------------
Strongswan is a popular IPsec implementation for the Linux kernel. While the actual encoding / decoding of IPsec packets takes place in the kernel's network stack, Strongswan's IKEv2 keying daemon _charon_ negotiates new SAs on behalf of the host according to a configured policy.

In this tutorial we are using instant Contiki 2.6 which is based upon Ubuntu, but any Debian-based system ought to work with these instructions.

Install Strongswan:	

	sudo apt-get install strongswan

Copy the configuration files:

	sudo cp scripts/strongswan/ipsec.conf scripts/strongswan/strongswan.conf scripts/strongswan/ipsec.secrets /etc/

Restart charon and associated systems:

	sudo sh scripts/strongswan/reset_ike_ipsec.sh

Strongswan should now be set up. If you want to know more about the configuration files, please see the section "IPsec without IKEv2 and other configurations".


Testing the Demonstration Setup
-------------------------------
The demonstration consists of one host sending a UDP packet on port 1234 to the other host. This will trigger an IKEv2 handshake as there are no SAs in place and the policy is set to require UDP traffic to be protected.

### Testing with the native target ###
While in the ipsec-example directory, run:

	make TARGET=native

If you've changed scripts/strongswan/strongswan.conf (which you probably have), please note that you have to make sure that your changes have been applied to /etc/strongswan.conf

Now, proceed to flush all SAs, policies and then restart the charon daemon:

	sudo scripts/strongswan/reset_ike_ipsec.sh

Run the native mote:

	make TARGET=native connect-router

Upon starting the mote, you should see something like the following:

	user@ubuntu:~/share/contiki-master/examples/ipsec$ make TARGET=native connect-router
	sudo ./ipsec-example.native -s /dev/null aaaa::1/64
	PID is 8974
	Contiki-2.6-199-ge1c5f6f started with IPV6, RPL
	Rime started with address 1.2.3.4.5.6.7.8
	MAC nullmac RDC nullrdc NETWORK sicslowpan
	IPsec: SAD and SPD initialized
	ECC INITIALIZED: key bit len: 192 NN_DIGIT_BITS: 16
	ike_statem_init: calling udp_new
	UIP_UDP_CONNS: 12
	UDP conn: 0, lport: 0
	returning 0x80729c4, lport 1025
	Setting 0x80729c4 to lport 500
	IPsec IKEv2: State machine initialized. Listening on UDP port 500.
	IPsec: IKEv2 service initialized
	Tentative link-local IPv6 address fe80:0000:0000:0000:0302:0304:0506:0708
	ipsec-example: calling udp_new
	UIP_UDP_CONNS: 12
	UDP conn: 0, lport: 500
	UDP conn: 1, lport: 0
	returning 0x80729e4, lport 1026
	Setting 0x80729e4 to lport 1234
	RPL-Border router started
	opened tun device ``/dev/tun0''
	ifconfig tun0 inet `hostname` up
	ifconfig tun0 add aaaa::1/64
	ifconfig tun0
	
	tun0      Link encap:UNSPEC  HWaddr 00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00  
	          inet addr:127.0.1.1  P-t-P:127.0.1.1  Mask:255.255.255.255
	          inet6 addr: aaaa::1/64 Scope:Global
	          UP POINTOPOINT RUNNING NOARP MULTICAST  MTU:1500  Metric:1
	          RX packets:0 errors:0 dropped:0 overruns:0 frame:0
	          TX packets:0 errors:0 dropped:0 overruns:0 carrier:0
	          collisions:0 txqueuelen:500 
	          RX bytes:0 (0.0 B)  TX bytes:0 (0.0 B)
	
	Setting prefix aaaa::1
	created a new RPL dag
	Server IPv6 addresses:
	 0x8072c48: =>aaaa::302:304:506:708
	 0x8072c68: =>fe80::302:304:506:708

You should now be able to communicate over IPsec by using the NetCat utility (provided by the Ubuntu package netcat-openbsd) to send the mote a UDP packet on port 1234. Type in another terminal:
	
	nc -u <the native mote's address> 1234

...and enter a random string of your liking. The small Contiki-app that listens on port 1234 should reply by taking each character and incrementing its value by one. For example, this was the output when the author entered the string "Contiki":

	user@ubuntu:~/share/contiki-master/examples/ipsec$ nc -u aaaa::302:304:506:708 1234
	Contiki
	Dpoujlj

Prior to receiving the reply, you should see intensive activity on the console where your native mote is running. It should be something like the following:

	IPv6 packet received from aaaa::1 to aaaa::302:304:506:708
	INCOMING IPsec PACKET PROCESSING
	Proc hdr 17
	Applicable packet policy:
	Selector: Action: BYPASS
	Offer at addr: (nil)
	Receiving UDP packet
	uip_udp_conn->lport 500, uip_udp_conn->rport 0
	IPsec IKEv2: Handling incoming request for a new IKE session
	IPsec: Allocating 204 bytes at 0x9ceb008. IPsec now has allocated 204 B memory
	IPsec IKEv2: Initiating IKE session 0x9ceb008
	IPsec: Allocating 824 bytes at 0x9ceb0d8. IPsec now has allocated 1028 B memory
	IPsec IKEv2: Generating private ECC key
	IPsec IKEv2: Session 0x9ceb008 is entering state 0x805d3fc
	IPsec IKEv2: ike_statem_state_respond_start: Entering
	Next payload is 33
	IPsec IKEv2: Peer proposal accepted
	Next payload is 34
	IPsec IKEv2: KE payload: Using DH group no. 25
	Next payload is 40
	IPsec IKEv2: Parsed 32 B long nonce from the peer
	Peer's nonce (len 32):
	0x9ceb122 (   0) 236edde1 9b3e3787 b7704126 0781e31e 
	0x9ceb132 (  16) ffa41c64 3528d61c ad4c0ef5 902be639 
	0x9ceb142 (  32) 201624c3 ca3e6d06 0c000000 00000000 
	Next payload is 41
	IPsec IKEv2: Received informative notify message of type no. 16388
	Next payload is 41
	IPsec IKEv2: Received informative notify message of type no. 16389
	IPsec IKEv2: Calculating shared ECC Diffie Hellman secret
	Shared ECC Diffie Hellman secret (g^ir) (len 24):
	0xbfa4627d (   0) 281bd666 9afacd98 af35e60b 4a214f76 
	0xbfa4628d (  16) cac30379 4788ac77 000000b8 62a4bf00 

... and so on. This is the IKE negotiation's diagnostic output. At the end of it both hosts (the mote and the PC) should have two new SAs (one for each traffic direction), evidence of which is displayed in /var/log/syslog and the diagnotic output. Running _sudo setkey -D_ on the host will give you the details.

If this doesn't work out for you, debugging can be tedious if you're not accustomed to Contiki and IPsec. I recommend you to read /var/log/syslog and make sure that charon's debug level is set sufficiently high in strongswan.conf (if you have used strongswan.conf from ipsec-example, it will be set accordingly). Other common problems are mis-set IP addresses in spd_conf.c or strongswan.conf. It can also be a good idea to run all reset scripts in scripts/ once more, just to make sure that everything really is ready to go.

Finally, this is what the tunnel interface looks like to me when the native mote is up and running. Please note the route to the tun0 interface in the second entry of the routing table.

	user@ubuntu:~/share/contiki-master/tools$ ifconfig
	eth0      Link encap:Ethernet  HWaddr 08:00:27:8d:af:42  
	          inet addr:10.0.2.15  Bcast:10.0.2.255  Mask:255.255.255.0
	          inet6 addr: fe80::a00:27ff:fe8d:af42/64 Scope:Link
	          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
	          RX packets:817745 errors:0 dropped:0 overruns:0 frame:0
	          TX packets:478434 errors:0 dropped:0 overruns:0 carrier:0
	          collisions:0 txqueuelen:1000 
	          RX bytes:317746348 (317.7 MB)  TX bytes:26547888 (26.5 MB)
	
	lo        Link encap:Local Loopback  
	          inet addr:127.0.0.1  Mask:255.0.0.0
	          inet6 addr: ::1/128 Scope:Host
	          UP LOOPBACK RUNNING  MTU:16436  Metric:1
	          RX packets:128 errors:0 dropped:0 overruns:0 frame:0
	          TX packets:128 errors:0 dropped:0 overruns:0 carrier:0
	          collisions:0 txqueuelen:0 
	          RX bytes:13188 (13.1 KB)  TX bytes:13188 (13.1 KB)
	
	tun0      Link encap:UNSPEC  HWaddr 00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00  
	          inet addr:127.0.1.1  P-t-P:127.0.1.1  Mask:255.255.255.255
	          inet6 addr: aaaa::1/64 Scope:Global
	          UP POINTOPOINT RUNNING NOARP MULTICAST  MTU:1500  Metric:1
	          RX packets:0 errors:0 dropped:0 overruns:0 frame:0
	          TX packets:0 errors:0 dropped:0 overruns:0 carrier:0
	          collisions:0 txqueuelen:500 
	          RX bytes:0 (0.0 B)  TX bytes:0 (0.0 B)
	
	user@ubuntu:~/share/contiki-master/tools$ route -6
	Kernel IPv6 routing table
	Destination                    Next Hop                   Flag Met Ref Use If
	::/0                           ::                         !n   -1  1 62779 lo
	aaaa::/64                      ::                         U    256 0     0 tun0
	fe80::/64                      ::                         U    256 0     0 eth0
	fe80::/64                      ::                         U    256 0     0 tun0
	::/0                           ::                         !n   -1  1 62779 lo
	::1/128                        ::                         Un   0   1    15 lo
	aaaa::1/128                    ::                         Un   0   1     0 lo
	fe80::a00:27ff:fe8d:af42/128   ::                         Un   0   1     0 lo
	ff00::/8                       ::                         U    256 0     0 eth0
	ff00::/8                       ::                         U    256 0     0 tun0
	::/0                           ::                         !n   -1  1 62779 lo
	

### Testing with Cooja ###
This guide outlines an experiment where Wismote (emulated in Cooja) performs a handshake with a Linux PC running the Strongswan IKEv2 service. The Linux PC will initiate the handshake, but the Wismote can do so as well. Another emulated mote in Cooja acts as a border router and forwards the packets between the PC and the IKEv2 mote.

First, make sure that you are using MSPGCC 4.7.2 or later as 4.7.0 will cause memory corruption. Also, check that UIP\_CONF\_BUFFER\_SIZE is at least 400 B large or packets may be silently dropped.

Procedure:

Compile the border router mote in examples/ipv6/rpl-border-router:

	make TARGET=wismote 

Compile the IPsec mote in examples/ipsec:

	make TARGET=wismote 

Start Cooja with the supplied simulation environment. It will use the RPL border router mote and the IPsec mote as compiled above (in examples/ipsec):

	make TARGET=cooja ipsec-example.csc

Wait till Cooja has loaded the CSC-file and then, in examples/ipv6/rpl-border-router:

	make TARGET=cooja connect-router-cooja

Enter any root password if necessary. Now, in Cooja, press the simulation start button.

In the terminal running the border router, you should now see something like:

	slip connected to ``127.0.0.1:60001''
	opened tun device ``/dev/tun0''
	ifconfig tun0 inet `hostname` up
	ifconfig tun0 add aaaa::1/64
	ifconfig tun0 add fe80::0:0:0:1/64
	ifconfig tun0
	
	tun0      Link encap:UNSPEC  HWaddr 00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00  
	          inet addr:127.0.1.1  P-t-P:127.0.1.1  Mask:255.255.255.255
	          inet6 addr: fe80::1/64 Scope:Link
	          inet6 addr: aaaa::1/64 Scope:Global
	          UP POINTOPOINT RUNNING NOARP MULTICAST  MTU:1500  Metric:1
	          RX packets:0 errors:0 dropped:0 overruns:0 frame:0
	          TX packets:0 errors:0 dropped:0 overruns:0 carrier:0
	          collisions:0 txqueuelen:500 
	          RX bytes:0 (0.0 B)  TX bytes:0 (0.0 B)


There should now be a network connection between the motes and the PC. You should get a response from the IPsec node by issuing:

	ping6 aaaa::200:0:0:2

Prepare the Strongswan service by installing the configuration files and reseting it, as explained in the previous example that used the native target. You should now be ready to attempt a handshake.

It is suggested that you leave a terminal window open with a tail of syslog so that you can see what's going on:
	
	sudo tail -f /var/log/syslog

Send a UDP packet:

	nc -u aaaa::200:0:0:2 1234

This will initiate the negotiation and after some time (can take a minute if your Virtual Machine is slow, as is the case for me) you should see something like the following in syslog:

	.
	.
	. (Sending IKE_SA_INIT request)
	Nov 15 14:56:11 instant-contiki charon: 15[ENC] generating IKE_SA_INIT request 0 [ SA KE No N(NATD_S_IP) N(NATD_D_IP) ]
	Nov 15 14:56:11 instant-contiki charon: 15[NET] sending packet: from aaaa::1[500] to aaaa::200:0:0:2[500]
 	.
	.
	. (Receiving IKE_SA_INIT response)
	Nov 15 14:57:05 instant-contiki charon: 01[NET] received packet: from aaaa::200:0:0:2[500] to aaaa::1[500]
	Nov 15 14:57:05 instant-contiki charon: 01[ENC] parsed IKE_SA_INIT response 0 [ SA KE No ]
	Nov 15 14:57:05 instant-contiki charon: 01[CFG] selecting proposal:
	Nov 15 14:57:05 instant-contiki charon: 01[CFG]   proposal matches
	Nov 15 14:57:05 instant-contiki charon: 01[CFG] received proposals: IKE:AES_CTR_128/AES_XCBC_96/PRF_HMAC_SHA1/E
	CP_192
	Nov 15 14:57:05 instant-contiki charon: 01[CFG] configured proposals: IKE:AES_CTR_128/AES_XCBC_96/HMAC_SHA1_96/
	PRF_AES128_XCBC/PRF_HMAC_SHA1/ECP_192
	Nov 15 14:57:05 instant-contiki charon: 01[CFG] selected proposal: IKE:AES_CTR_128/AES_XCBC_96/PRF_HMAC_SHA1/EC
	P_192
	Nov 15 14:57:05 instant-contiki charon: 01[IKE] shared Diffie Hellman secret => 24 bytes @ 0xb7806348
	Nov 15 14:57:05 instant-contiki charon: 01[IKE]    0: 70 83 79 30 DF 96 AB 63 64 C7 5C 6B 47 27 CF EB  p.y0...cd.\kG'..
	Nov 15 14:57:05 instant-contiki charon: 01[IKE]   16: 09 C3 F7 51 8B 9D FB 37	.
	.
	.
	. (Sending IKE_AUTH request)
	Nov 15 14:57:05 instant-contiki charon: 01[KNL] got SPI c4c32caa for reqid {2}
	Nov 15 14:57:05 instant-contiki charon: 01[ENC] generating IKE_AUTH request 1 [ IDi N(INIT_CONTACT) AUTH N(USE_TRANSP) SA TSi TSr N(EAP_ONLY) ]
	Nov 15 14:57:05 instant-contiki charon: 01[NET] sending packet: from aaaa::1[500] to aaaa::200:0:0:2[500]
	.
	.
	. (IKE SA established)
	Nov 15 14:57:34 instant-contiki charon: 11[IKE]   16: 98 D3 FB A6                                      ....
	Nov 15 14:57:34 instant-contiki charon: 11[IKE] authentication of 'ville@sics.se   ' with pre-shared key succes
	sful
	Nov 15 14:57:34 instant-contiki charon: 11[IKE] IKE_SA cooja_host-host[1] established between aaaa::1[strongswa
	n]...aaaa::200:0:0:2[ville@sics.se   ]
	Nov 15 14:57:34 instant-contiki charon: 11[IKE] IKE_SA cooja_host-host[1] state change: CONNECTING => ESTABLISH
	ED
	.
	.
	. (Receving IKE_AUTH response)
	Nov 15 14:57:34 instant-contiki charon: 11[NET] received packet: from aaaa::200:0:0:2[500] to aaaa::1[500]
	Nov 15 14:57:34 instant-contiki charon: 11[ENC] parsed IKE_AUTH response 1 [ IDr AUTH N(USE_TRANSP) SA TSi TSr ]
	Nov 15 14:57:34 instant-contiki charon: 11[IKE] received USE_TRANSPORT_MODE notify
	.
	.
	. (Child SA:s established)
	Nov 15 14:57:37 instant-contiki charon: 11[IKE] CHILD_SA cooja_host-host{2} established with SPIs c4c32caa_i e8 030000_o and TS aaaa::1/128 === aaaa::200:0:0:2/128 
	

You can now enter more data into nc (netcat) and the IPsec mote should echo it back, but with the value of each byte incremented by one (e.g. 1234 => 2345).

IPsec without IKEv2
===================
As explained in RFC 4301 (Security Architecture for the Internet Protocol), an automatic keying service such as IKEv2 is not required to establish SAs. An SA pair can also be manually set up by the administrators of the respective hosts. This is most helpful if you have a host with restrained memory and a small set of hosts which it communicates with.

This example is identical to previous, but IKEv2 is disabled on both hosts and the SAs are manually set up.

Contiki configuration
---------------------
Set the following in examples/ipsec/ipsec-conf.h:
	WITH\_CONF\_IPSEC\_IKE	0
	WITH\_CONF\_MANUAL\_SA	1

The SAs can now be configured in core/net/ipsec/sad_conf.c. The encryption keys and addresses given in the example there matches those on the Linux box at ipsec-tols-esp.conf (see more below). Please note that you have to change the hosts' addresses (coojanative and molniya). The encryption keys given should only be used for testing. 


Linux configuration
-------------------
The SAs are set using the ipsec-tools package's *setkey* command. An example of this is available in the file examples/ipsec/scripts/ipsec-tools-esp.conf. Please note that you have to change the hosts' addresses (coojanative and molniya). The encryption keys given in the file should only be used for testing. 

Testing
-------
The test procedure and the result should be the same as for the earlier IKEv2 example, but now the IKEv2 service will not be invoked as the SAs are already in place.

Fault tracing
=============
Here follows a couple of suggestions of what to do when things don't go as expected. It's given under the presumption that the reader is accustomed to debugging in Contiki.

* If you are using MSPGCC, please check that you're using 4.7.2 or above. 4.7.0 is known to cause crashes.
* Assert that you're using Instant Contiki 2.6.1 which is known to work.
* Are your IP packet buffers large enough? If not, your Contiki nodes will silently drop your large IKEv2 packets. Check the UIP\_CONF\_BUFFER\_SIZE define and please note that it can be overridden in various platform specific header files. Choose at least 800 bytes if you're uncertain of an ok size. (However, you should be able to squeeze it down towards 300 B if you've set up Strongswan correctly.)
* Use the Wireshark network debug utility. It's great to know what's going on in the network.
* If you're uncertain what compilation flags the build process is giving to the compiler, try adding V=1 to the make command for more verbosity.

Debuging options can be set in uip6.c and ipsec.h.

About this implementation
=========================
This is a partial implementation of RFC 4301 (IPsec) and RFC 5996 (IKEv2) along with associated standards written by Vilhelm Jutvik (ville@imorgon.se) as his MS Thesis Project at [SICS](sics.se)). It's an extension / rework of Simon Duquennoy's (simonduq@sics.se) IPsec implementation (also a [SICS](sics.se) work [paper](http://www.simonduquennoy.net/papers/raza11securing-demo.pdf)). The ECC library is a port of TinyECC to Contiki, provided by Kasun Hewage (kasun.hewage@it.uu.se) under the directions of [SICS](sics.se).

Thanks to Alex Papanikolaou who contacted me and gave valuable feedback on this README-file along with a small patch of improvements!

Future work
===========
The static nature of the SPD is not suitable for the Internet of Things as the network structure of the latter is dynamic. This becomes apparent when using RPL as one would often like to make the information provided by RPL the basis of an IPsec policy. This is not possible with the SPD as described in RFC 4301.

For reasons outlined in the author's thesis, AH is redundant and he can not recommend its implementation.