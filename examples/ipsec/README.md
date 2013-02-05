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
* Only tunnel mode supported
* EAP
* No NAT support whatsoever, anywhere
* No IPcomp support
* Only IDs of type ID\_RFC822\_ADDR (e-mail address) are supported
* No support for Certificates as IDs, nor for authentication


### Basic features that ought to be implemented in IKEv2 ###
* Deletion of Child and IKE SAs (Delete payload)
* State machine Established can't create child SAs currently
 
Performance
===========
Todo: Information about Memory and CPU

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

The declaration of the SPD is made in the array spd\_table located in the file core/net/ipsec/spc\_conf.c, line 127. Whenever an IP-packet is about to enter or leave the system (forwarded packets are not considered though), the array is traversed from the top to the bottom until a rule with a matching traffic pattern is found. The existing table is suited to the example in this README, but *you must substitute the IPv6-addresses used therein with those of your system*. Failure to do so will result in an inoperative system.

More help is available in the source code's comments and section 4.4.1 of RFC 4301.


Building Contiki with IPsec and IKEv2
-------------------------------------
The Contiki system can be built and run on any machine. As IPsec is a part of the IPv6 stack, the only requirement is that they must be able to communicate over IPv6.


### The Wismote (MSP430x) Target ###
The [Wismote](http://wismote.org/) is a suitable test platform for IPsec as it provides ample RAM and FLASH. It can also be emulated in Cooja which makes it even more attractive for experimentation.

Even though Wismote can run MSP430-binaries compiled with GCC, this IPsec patch must be compiled using the MSP430X instruction set (20-bit memory instructions) as the memory space provided by the 16-bit MSP430 is not enough. As of January 2013, support for this target has still not made it to mainline MSPGCC. Therefore the build system is set up for using a compiler from [IAR Systems](http://www.iar.com) that only runs Windows environments.

Therefore, the recommended procedure is to check out this code in MS Windows, and execute the following in a Cygwin environment running on top of it (while in the directory examples/ipsec):
	make TARGET=wismote


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

In this tutorial we are using instant Contiki 2.5 which is based upon Ubuntu, but any Debian-based system ought to work.

1. Install Strongswan
	sudo apt-get install strongswan
2. Copy the configuration files
	cp scripts/strongswan/ipsec.conf scripts/strongswan/strongswan.conf scripts/strongswan/ipsec.secrets /etc/
3. Restart charon and associated systems
	sudo sh scripts/strongswan/reset\_ike\_ipsec.sh

Strongswan should now be set up. If you want to know more about the configuration files, please see the section "IPsec without IKEv2 and other configurations".


Testing the Demonstration Setup
-------------------------------
The demonstration consists of one host sending a UDP packet on port 1234 to the other host. This will trigger an IKEv2 handshake as there are no SAs in place and the policy is set to require UDP traffic to be protected.

### Testing with the native target ###
TODO Real Soon Now
Contact ville@imorgon.se for instructions

### Testing with Cooja ###
TODO Real Soon Now
Contact ville@imorgon.se for instructions


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

TODO: Write something more

About this implementation
=========================
This is a partial implementation of RFC 4301 (IPsec) and RFC 5996 (IKEv2) along with associated standards written by Vilhelm Jutvik (ville@imorgon.se) as his MS Thesis Project at [SICS](sics.se)). It's an extension / rework of Simon Duquennoy's (simonduq@sics.se) IPsec implementation (also a [SICS](sics.se) work [paper](http://www.simonduquennoy.net/papers/raza11securing-demo.pdf)). The ECC library is a port of TinyECC to Contiki, provided by Kasun Hewage (kasun.hewage@it.uu.se) under the directions of [SICS](sics.se).

Future work
===========
The static nature of the SPD is not suitable for the Internet of Things as the network structure of the latter is dynamic. This becomes apparent when using RPL as one would often like to make the information provided by RPL the basis of an IPsec policy. This is not possible with the SPD as described in RFC 4301.

For reasons outlined in the author's thesis, AH is redundant and he can not recommend its implementation.