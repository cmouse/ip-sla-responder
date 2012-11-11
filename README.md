Cisco IP-SLA / Juniper RPM responder
====================================

Contents
--------

1. About
2. Installation
3. Usage
4. TODO

About
-----

This program is intended for Cisco IP-SLA and Juniper PRM measurements. You can configure it to listen on any ethernet interface, and it'll reply to you. It expects all packets to be 802.1q encapsulated, and it works best if you do not configure any vlans into your system. IP and MAC address can be freely chosen, and do not need to be configured on your system.

Installation
------------

To install, run make (or gmake). This software expects linux 2.6 or better kernel, or kernel with similar facilities. It needs pcap(3) interface on kernel and AF_PACKET. It also requires librt and libpcap. 

Usage
-----

The software can run in either routed or connected mode. In routed mode, you are expected to route in some IP via some VLAN. At the moment it will not work w/o VLANs. In connected mode, you can have one or more vlans configured with same network on the network side, and nothing on linux side. Best if you don't configure any vlans and leave the interface offline, so linux or the nic won't eat up your packets. 

Run the software, no arguments are required, defaults are used instead. To see these, run with -h. 

After this, you can point Cisco IP SLA UDP Jitter measurements, or Juniper RPM icmp-ping(-timestamp) or udp-ping(-timestamp) measurements towards the IP. It'll reply these.

TODO
----

 * Fix debugging to actually do something
 * Add more supported types for Cisco
 * Daemonize?
 * Code cleanup and documentation
